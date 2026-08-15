static OPJ_BOOL opj_j2k_write_first_tile_part(opj_j2k_t *p_j2k,
        OPJ_BYTE * p_data,
        OPJ_UINT32 * p_data_written,
        OPJ_UINT32 p_total_data_size,
        opj_stream_private_t *p_stream,
        struct opj_event_mgr * p_manager)
{
    OPJ_UINT32 l_nb_bytes_written = 0;
    OPJ_UINT32 l_current_nb_bytes_written;
    OPJ_BYTE * l_begin_data = 00;

    opj_tcd_t * l_tcd = 00;
    opj_cp_t * l_cp = 00;

    l_tcd = p_j2k->m_tcd;
    l_cp = &(p_j2k->m_cp);

    l_tcd->cur_pino = 0;

    /*Get number of tile parts*/
    p_j2k->m_specific_param.m_encoder.m_current_poc_tile_part_number = 0;

    /* INDEX >> */
    /* << INDEX */

    l_current_nb_bytes_written = 0;
    l_begin_data = p_data;
    if (! opj_j2k_write_sot(p_j2k, p_data, &l_current_nb_bytes_written, p_stream,
                            p_manager)) {
        return OPJ_FALSE;
    }

    l_nb_bytes_written += l_current_nb_bytes_written;
    p_data += l_current_nb_bytes_written;
    p_total_data_size -= l_current_nb_bytes_written;

    if (!OPJ_IS_CINEMA(l_cp->rsiz)) {
#if 0
        for (compno = 1; compno < p_j2k->m_private_image->numcomps; compno++) {
            l_current_nb_bytes_written = 0;
            opj_j2k_write_coc_in_memory(p_j2k, compno, p_data, &l_current_nb_bytes_written,
                                        p_manager);
            l_nb_bytes_written += l_current_nb_bytes_written;
            p_data += l_current_nb_bytes_written;
            p_total_data_size -= l_current_nb_bytes_written;

            l_current_nb_bytes_written = 0;
            opj_j2k_write_qcc_in_memory(p_j2k, compno, p_data, &l_current_nb_bytes_written,
                                        p_manager);
            l_nb_bytes_written += l_current_nb_bytes_written;
            p_data += l_current_nb_bytes_written;
            p_total_data_size -= l_current_nb_bytes_written;
        }
#endif
        if (l_cp->tcps[p_j2k->m_current_tile_number].numpocs) {
            l_current_nb_bytes_written = 0;
            opj_j2k_write_poc_in_memory(p_j2k, p_data, &l_current_nb_bytes_written,
                                        p_manager);
            l_nb_bytes_written += l_current_nb_bytes_written;
            p_data += l_current_nb_bytes_written;
            p_total_data_size -= l_current_nb_bytes_written;
        }
    }

    l_current_nb_bytes_written = 0;
    if (! opj_j2k_write_sod(p_j2k, l_tcd, p_data, &l_current_nb_bytes_written,
                            p_total_data_size, p_stream, p_manager)) {
        return OPJ_FALSE;
    }

    l_nb_bytes_written += l_current_nb_bytes_written;
    * p_data_written = l_nb_bytes_written;

    /* Writing Psot in SOT marker */
    opj_write_bytes(l_begin_data + 6, l_nb_bytes_written,
                    4);                                 /* PSOT */

    if (OPJ_IS_CINEMA(l_cp->rsiz)) {
        opj_j2k_update_tlm(p_j2k, l_nb_bytes_written);
    }

    return OPJ_TRUE;
}