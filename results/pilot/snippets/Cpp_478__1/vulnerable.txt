int IMA::decodeBlockQT(const uint8_t *encoded, int16_t *decoded)
{
	int channelCount = m_track->f.channelCount;

	for (int c=0; c<channelCount; c++)
	{
		adpcmState state;
		int predictor = (encoded[0] << 8) | (encoded[1] & 0x80);
		if (predictor & 0x8000)
			predictor -= 0x10000;

		state.previousValue = clamp(predictor, MIN_INT16, MAX_INT16);
		state.index = encoded[1] & 0x7f;
		encoded += 2;

		for (int n=0; n<m_framesPerPacket; n+=2)
		{
			uint8_t e = *encoded;
			decoded[n*channelCount + c] = decodeSample(state, e & 0xf);
			decoded[(n+1)*channelCount + c] = decodeSample(state, e >> 4);
			encoded++;
		}
	}

	return m_framesPerPacket * channelCount * sizeof (int16_t);
}
