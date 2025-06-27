
#ifndef __MLX5E_TRB_FS_H__
#define __MLX5E_TRB_FS_H__

#include "en/fs.h"

enum trb_fs_types {
        TRB_FS_IPV4_TCP,
        TRB_FS_IPV4_UDP,
        TRB_FS_NUM_TYPES,
};


struct trb_params {
        enum trb_fs_types type;
        uint16_t dport;
};

int mlx5e_create_trb_table(struct mlx5e_flow_steering *fs, struct mlx5e_rx_res *res, struct trb_params *params);


#endif
