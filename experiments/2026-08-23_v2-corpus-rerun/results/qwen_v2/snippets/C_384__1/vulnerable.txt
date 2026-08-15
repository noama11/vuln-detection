static OPJ_BOOL opj_j2k_write_sot(opj_j2k_t *p_j2k,
                                  OPJ_BYTE * p_data,
                                  OPJ_UINT32 * p_data_written,
                                  const opj_stream_private_t *p_stream,
                                  opj_event_mgr_t * p_manager
                                 )
{
    /* preconditions */
    assert(p_j2k != 00);
    assert(p_manager != 00);
    assert(p_stream != 00);

    OPJ_UNUSED(p_stream);
    OPJ_UNUSED(p_manager);

    opj_write_bytes(p_data, J2K_MS_SOT,
                    2);                                 /* SOT */
    p_data += 2;

    opj_write_bytes(p_data, 10,
                    2);                                                   /* Lsot */
    p_data += 2;

    opj_write_bytes(p_data, p_j2k->m_current_tile_number,
                    2);                        /* Isot */
    p_data += 2;

    /* Psot  */
    p_data += 4;

    opj_write_bytes(p_data,
                    p_j2k->m_specific_param.m_encoder.m_current_tile_part_number,
                    1);                        /* TPsot */
    ++p_data;

    opj_write_bytes(p_data,
                    p_j2k->m_cp.tcps[p_j2k->m_current_tile_number].m_nb_tile_parts,
                    1);                      /* TNsot */
    ++p_data;

    /* UniPG>> */
#ifdef USE_JPWL
    /* update markers struct */
    /*
            OPJ_BOOL res = j2k_add_marker(p_j2k->cstr_info, J2K_MS_SOT, p_j2k->sot_start, len + 2);
    */
    assert(0 && "TODO");
#endif /* USE_JPWL */

    * p_data_written = 12;

    return OPJ_TRUE;
}