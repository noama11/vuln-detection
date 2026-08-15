void LibRaw::exp_bef(float shift, float smooth)
{
    // params limits
    if(shift>8) shift = 8;
    if(shift<0.25) shift = 0.25;
    if(smooth < 0.0) smooth = 0.0;
    if(smooth > 1.0) smooth = 1.0;
    
    unsigned short *lut = (ushort*)malloc((TBLN+1)*sizeof(unsigned short));

    if(shift <=1.0)
        {
            for(int i=0;i<=TBLN;i++)
                lut[i] = (unsigned short)((float)i*shift);
        }
    else
        {
            float x1,x2,y1,y2;

            float cstops = log(shift)/log(2.0f);
            float room = cstops*2;
            float roomlin = powf(2.0f,room);
            x2 = (float)TBLN;
            x1 = (x2+1)/roomlin-1;
            y1 = x1*shift;
            y2 = x2*(1+(1-smooth)*(shift-1));
            float sq3x=powf(x1*x1*x2,1.0f/3.0f);
            float B = (y2-y1+shift*(3*x1-3.0f*sq3x)) / (x2+2.0f*x1-3.0f*sq3x);
            float A = (shift - B)*3.0f*powf(x1*x1,1.0f/3.0f);
            float CC = y2 - A*powf(x2,1.0f/3.0f)-B*x2;
            for(int i=0;i<=TBLN;i++)
                {
                    float X = (float)i;
                    float Y = A*powf(X,1.0f/3.0f)+B*X+CC;
                    if(i<x1)
                        lut[i] = (unsigned short)((float)i*shift);
                    else
                        lut[i] = Y<0?0:(Y>TBLN?TBLN:(unsigned short)(Y));
                }
        }
    for(int i=0; i< S.height*S.width; i++)
        {
            imgdata.image[i][0] = lut[imgdata.image[i][0]];
            imgdata.image[i][1] = lut[imgdata.image[i][1]];
            imgdata.image[i][2] = lut[imgdata.image[i][2]];
            imgdata.image[i][3] = lut[imgdata.image[i][3]];
        }

    C.data_maximum = lut[C.data_maximum];
    C.maximum = lut[C.maximum];
    // no need to adjust the minumum, black is already subtracted
    free(lut);
}