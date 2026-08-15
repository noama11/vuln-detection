static OPJ_BOOL opj_j2k_write_all_tile_parts(opj_j2k_t *p_j2k,
        OPJ_BYTE * p_data,
        OPJ_UINT32 * p_data_written,
        OPJ_UINT32 p_total_data_size,
        opj_stream_private_t *p_stream,
        struct opj_event_mgr * p_manager
                                            )
{
    OPJ_UINT32 tilepartno = 0;
    OPJ_UINT32 l_nb_bytes_written = 0;
    OPJ_UINT32 l_current_nb_bytes_written;
    OPJ_UINT32 l_part_tile_size;
    OPJ_UINT32 tot_num_tp;
    OPJ_UINT32 pino;

    OPJ_BYTE * l_begin_data;
    opj_tcp_t *l_tcp = 00;
    opj_tcd_t * l_tcd = 00;
    opj_cp_t * l_cp = 00;

    l_tcd = p_j2k->m_tcd;
    l_cp = &(p_j2k->m_cp);
    l_tcp = l_cp->tcps + p_j2k->m_current_tile_number;

    /*Get number of tile parts*/
    tot_num_tp = opj_j2k_get_num_tp(l_cp, 0, p_j2k->m_current_tile_number);

    /* start writing remaining tile parts */
    ++p_j2k->m_specific_param.m_encoder.m_current_tile_part_number;
    for (tilepartno = 1; tilepartno < tot_num_tp ; ++tilepartno) {
        p_j2k->m_specific_param.m_encoder.m_current_poc_tile_part_number = tilepartno;
        l_current_nb_bytes_written = 0;
        l_part_tile_size = 0;
        l_begin_data = p_data;

        if (! opj_j2k_write_sot(p_j2k, p_data, &l_current_nb_bytes_written, p_stream,
                                p_manager)) {
            return OPJ_FALSE;
        }

        l_nb_bytes_written += l_current_nb_bytes_written;
        p_data += l_current_nb_bytes_written;
        p_total_data_size -= l_current_nb_bytes_written;
        l_part_tile_size += l_current_nb_bytes_written;

        l_current_nb_bytes_written = 0;
        if (! opj_j2k_write_sod(p_j2k, l_tcd, p_data, &l_current_nb_bytes_written,
                                p_total_data_size, p_stream, p_manager)) {
            return OPJ_FALSE;
        }

        p_data += l_current_nb_bytes_written;
        l_nb_bytes_written += l_current_nb_bytes_written;
        p_total_data_size -= l_current_nb_bytes_written;
        l_part_tile_size += l_current_nb_bytes_written;

        /* Writing Psot in SOT marker */
        opj_write_bytes(l_begin_data + 6, l_part_tile_size,
                        4);                                   /* PSOT */

        if (OPJ_IS_CINEMA(l_cp->rsiz)) {
            opj_j2k_update_tlm(p_j2k, l_part_tile_size);
        }

        ++p_j2k->m_specific_param.m_encoder.m_current_tile_part_number;
    }

    for (pino = 1; pino <= l_tcp->numpocs; ++pino) {
        l_tcd->cur_pino = pino;

        /*Get number of tile parts*/
        tot_num_tp = opj_j2k_get_num_tp(l_cp, pino, p_j2k->m_current_tile_number);
        for (tilepartno = 0; tilepartno < tot_num_tp ; ++tilepartno) {
            p_j2k->m_specific_param.m_encoder.m_current_poc_tile_part_number = tilepartno;
            l_current_nb_bytes_written = 0;
            l_part_tile_size = 0;
            l_begin_data = p_data;

            if (! opj_j2k_write_sot(p_j2k, p_data, &l_current_nb_bytes_written, p_stream,
                                    p_manager)) {
                return OPJ_FALSE;
            }

            l_nb_bytes_written += l_current_nb_bytes_written;
            p_data += l_current_nb_bytes_written;
            p_total_data_size -= l_current_nb_bytes_written;
            l_part_tile_size += l_current_nb_bytes_written;

            l_current_nb_bytes_written = 0;

            if (! opj_j2k_write_sod(p_j2k, l_tcd, p_data, &l_current_nb_bytes_written,
                                    p_total_data_size, p_stream, p_manager)) {
                return OPJ_FALSE;
            }

            l_nb_bytes_written += l_current_nb_bytes_written;
            p_data += l_current_nb_bytes_written;
            p_total_data_size -= l_current_nb_bytes_written;
            l_part_tile_size += l_current_nb_bytes_written;

            /* Writing Psot in SOT marker */
            opj_write_bytes(l_begin_data + 6, l_part_tile_size,
                            4);                                   /* PSOT */

            if (OPJ_IS_CINEMA(l_cp->rsiz)) {
                opj_j2k_update_tlm(p_j2k, l_part_tile_size);
            }

            ++p_j2k->m_specific_param.m_encoder.m_current_tile_part_number;
        }
    }

    *p_data_written = l_nb_bytes_written;

    return OPJ_TRUE;
}