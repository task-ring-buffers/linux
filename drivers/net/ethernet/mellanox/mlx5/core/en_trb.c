#include <mlx5_core.h>
#include "en_trb.h"
#include "fs_core.h"
#include "en/rx_res.h"

#define MLX5_TRB_NUM_GROUPS 2
#define MLX5_TRB_GROUP1_SIZE 4
#define MLX5_TRB_DEFAULT_GROUP_SIZE 1
#define MLX5E_TRB_TABLE_SIZE   (MLX5_TRB_GROUP1_SIZE +\
                                         MLX5_TRB_DEFAULT_GROUP_SIZE)


/* We can only have either udp or tcp flow entries at a time in the flow table. Only 2 groups exist a time, udp/tcp and default*/


enum mlx5_traffic_types fs_trb2tt(enum trb_fs_types i)
{
        switch (i) {
        case TRB_FS_IPV4_TCP:
                return MLX5_TT_IPV4_TCP;
        default:
		return MLX5_TT_IPV4_UDP;
        }
}


struct mlx5e_trb_table {
	int num_groups;
	struct mlx5_flow_table *t;
	struct mlx5_flow_group **g;
	struct mlx5_flow_handle *trb_rules[2];
};



int trb_ft_enable(struct mlx5e_flow_steering *fs, enum trb_fs_types type)
{
	struct mlx5e_trb_table *trb = mlx5e_fs_get_trb(fs);
	struct mlx5_ttc_table *ttc = mlx5e_fs_get_ttc(fs, false);
	struct mlx5_flow_destination dest = {};
	int err = 0;

	dest.type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	dest.ft = trb->t;
	err = mlx5_ttc_fwd_dest(ttc, fs_trb2tt(type), &dest);
	if (err)
		pr_warn("Failed to modify ttc dest\n");

	//pr_warn("Successfully set dest for TT=%d\n", fs_trb2tt(type));

	return err;
}
int trb_create_port_rule(struct mlx5e_flow_steering *fs, enum trb_fs_types type, struct mlx5_flow_destination *custom_dest, uint16_t dport)
{
	struct mlx5e_trb_table *trb = mlx5e_fs_get_trb(fs);
        // struct mlx5_ttc_table *ttc = mlx5e_fs_get_ttc(fs, false);
        MLX5_DECLARE_FLOW_ACT(flow_act);
        struct mlx5_flow_handle *flow;
	struct mlx5_flow_spec *spec;
        int err = 0;

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec)
		return -ENOMEM;
	spec->match_criteria_enable = MLX5_MATCH_OUTER_HEADERS;

	MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria, outer_headers.ip_protocol);
	switch(type) {
		case TRB_FS_IPV4_TCP:
			MLX5_SET(fte_match_param, spec->match_value, outer_headers.ip_protocol, IPPROTO_TCP);
			MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria, outer_headers.tcp_dport);
			MLX5_SET(fte_match_param, spec->match_value, outer_headers.tcp_dport, dport);
			break;
		case TRB_FS_IPV4_UDP:
			MLX5_SET(fte_match_param, spec->match_value, outer_headers.ip_protocol, IPPROTO_UDP);
			MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria, outer_headers.udp_dport);
			MLX5_SET(fte_match_param, spec->match_value, outer_headers.udp_dport, dport);
			break;
		default:
			break;
	}

	MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria, outer_headers.ip_version);
	MLX5_SET(fte_match_param, spec->match_value, outer_headers.ip_version, 4);
	flow = mlx5_add_flow_rules(trb->t, spec, &flow_act, custom_dest, 1);

	if (IS_ERR(flow)){
		err = PTR_ERR(flow);
		pr_warn("Cannot add custom flow rule\n");
		goto out;
	}

	//pr_warn("Successfully created flow rule for type %d and set dest as %p\n", fs_trb2tt(type), custom_dest);

	trb->trb_rules[1] = flow;

out:
	kvfree(spec);
	return err;

}

int trb_create_default_rule(struct mlx5e_flow_steering *fs, struct mlx5_flow_destination *def_dest)
{
	struct mlx5e_trb_table *trb = mlx5e_fs_get_trb(fs);
	// struct mlx5_ttc_table *ttc = mlx5e_fs_get_ttc(fs, false);
	MLX5_DECLARE_FLOW_ACT(flow_act);
	struct mlx5_flow_handle *rule;
	int err = 0;

	rule = mlx5_add_flow_rules(trb->t, NULL, &flow_act, def_dest, 1);
	if (IS_ERR(rule)) {
		err = PTR_ERR(rule);
		pr_warn("Failed to add default rule\n");
		return err;
	}
	//pr_warn("Successfully created default flow rule and set dest as %p\n", def_dest);
	trb->trb_rules[0] = rule;
	return 0;
}



int trb_create_rules(struct mlx5e_flow_steering *fs, enum trb_fs_types type, struct mlx5_flow_destination *def_dest, struct mlx5_flow_destination *custom_dest, uint16_t dport)
{
	int err;
	err = trb_create_default_rule(fs, def_dest);
	if (err)
		return err;
	err = trb_create_port_rule(fs, type, custom_dest, dport);
	return err;

}
int trb_create_groups(struct mlx5e_trb_table *trb, enum trb_fs_types type)
{
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	void *outer_headers_c;
	int ix = 0;
	u32 *in;
	int err;
	u8 *mc;

	trb->g = kcalloc(MLX5_TRB_NUM_GROUPS, sizeof(*trb->g), GFP_KERNEL);
	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in || !trb->g) {
		kfree(trb->g);
		trb->g = NULL;
		kvfree(in);
		return -ENOMEM;
	}

	mc = MLX5_ADDR_OF(create_flow_group_in, in, match_criteria);
	outer_headers_c = MLX5_ADDR_OF(fte_match_param, mc, outer_headers);
	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c, ip_protocol);
	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c, ip_version);

	switch (type) {
		case TRB_FS_IPV4_TCP:
			MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c, tcp_dport);
			break;
		case TRB_FS_IPV4_UDP:
			//recheck this rule if it's correct
			MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c, udp_dport);
		break;
		default:
			err = -EINVAL;
			goto out;
	}

	MLX5_SET_CFG(in, match_criteria_enable, MLX5_MATCH_OUTER_HEADERS);
	MLX5_SET_CFG(in, start_flow_index, ix);
	ix += MLX5_TRB_GROUP1_SIZE;
	MLX5_SET_CFG(in, end_flow_index, ix - 1);
	trb->g[trb->num_groups] = mlx5_create_flow_group(trb->t, in);
	if (IS_ERR(trb->g[trb->num_groups]))
			goto err;

	pr_warn("Created the custom group\n");
	trb->num_groups++;

	/*Default Flow Group */
	memset(in, 0, inlen);
	MLX5_SET_CFG(in, start_flow_index, ix);
	ix += MLX5_TRB_DEFAULT_GROUP_SIZE;
	MLX5_SET_CFG(in, end_flow_index, ix - 1);
	trb->g[trb->num_groups] = mlx5_create_flow_group(trb->t, in);
	if (IS_ERR(trb->g[trb->num_groups]))
		goto err;
	pr_warn("Created the default group\n");
	trb->num_groups++;

	kvfree(in);
	return 0;

err:
	err = PTR_ERR(trb->g[trb->num_groups]);
	trb->g[trb->num_groups] = NULL;

out:
	kvfree(in);
	return err;
}

void mlx5_destroy_trb_table(struct mlx5e_flow_steering *fs)
{
	struct mlx5e_trb_table *trb = mlx5e_fs_get_trb(fs);
	int i;
	/* TODO */
	//disable trb
	if(IS_ERR_OR_NULL(trb->t))
		return;
	if(!IS_ERR_OR_NULL(trb->trb_rules[0]))
		mlx5_del_flow_rules(trb->trb_rules[0]);
	if (!IS_ERR_OR_NULL(trb->trb_rules[1]))
		mlx5_del_flow_rules(trb->trb_rules[1]);

	for (i = trb->num_groups - 1; i >= 0; i--) {
		if (!IS_ERR_OR_NULL(trb->g[i]))
			mlx5_destroy_flow_group(trb->g[i]);
		trb->g[i] = NULL;
	}

	trb->num_groups = 0;
	kfree(trb);
	mlx5e_fs_set_trb(fs, NULL);
}

int mlx5e_create_trb_table(struct mlx5e_flow_steering *fs, struct mlx5e_rx_res *res, struct trb_params *params)
{
	bool match_ipv_outer = MLX5_CAP_FLOWTABLE_NIC_RX(mlx5e_fs_get_mdev(fs), ft_field_support.outer_ip_version);
	struct mlx5_flow_namespace *ns = mlx5e_fs_get_ns(fs, false);
	struct mlx5e_trb_table *trb;
	struct mlx5_flow_destination def_dest = {};
	struct mlx5_flow_destination custom_dest = {};
	int err;
	struct mlx5_flow_table_attr ft_attr = {};

	if (!match_ipv_outer)
		return -EOPNOTSUPP;

	trb = kvzalloc(sizeof(*trb), GFP_KERNEL);
	if(!trb)
		return -ENOMEM;

	mlx5e_fs_set_trb(fs, trb);

	ft_attr.max_fte = MLX5E_TRB_TABLE_SIZE;
	ft_attr.level = MLX5E_INNER_TTC_FT_LEVEL + 1;
	ft_attr.prio = MLX5E_NIC_PRIO;

	trb->num_groups = 0;
	trb->t = mlx5_create_flow_table(ns, &ft_attr);
	if (IS_ERR(trb->t)) {
		err = PTR_ERR(trb->t);
		kvfree(trb);
		pr_warn("Cannot create trb flow table\n");
		return err;
	}

	err = trb_create_groups(trb, params->type);
	if (err){
		pr_warn("Cannot create trb groups \n");
		goto err;
	}

	def_dest.type = MLX5_FLOW_DESTINATION_TYPE_TIR;
	custom_dest.type = MLX5_FLOW_DESTINATION_TYPE_TIR;
	def_dest.tir_num = mlx5e_rx_res_get_trb_tirn(res, 0);
	custom_dest.tir_num = mlx5e_rx_res_get_trb_tirn(res, 1);

	err = trb_create_rules(fs, params->type, &def_dest, &custom_dest, params->dport);
	if (err)
		goto err;

	err = trb_ft_enable(fs, params->type);
	if (err)
		goto err;
	return 0;

err:
	mlx5_destroy_trb_table(fs);
	return err;

}


