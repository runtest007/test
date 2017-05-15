/***********************************************************************
 *     
 *  Filename    :	uuptDecrypt.cpp
 *
 *  Author      :	gpengyuan
 *  Create      :	2016-11-30
 *
 *  Description :	
 				
 *                            
 *  Copyright (C), 2016, Beijing Run.Co., Ltd.
 *
 *  ChangeLog   :  
 *
 ***********************************************************************/
#include "uuptDecrypt.h"

#define CRYPTDATA_LENTH 1792	//密文十六进制字符串长度
#define DECRYPT_KEY_LENTH 8	//秘钥长度

//登录秘钥固定不变
//unsigned char DeCryptKey[DECRYPT_KEY_LENTH] = { 0x75, 0x75, 0x6D, 0x6F, 0x6E, 0x65, 0x79, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31 };
//短信登录加密数据
//unsigned char CryptDataContent[CRYPTDATA_LENTH + 1] = "3F4B62378EE47EC5AB002DCBEB4A4C8DE315FD824A4F00C28B71F31008A0AA2C5BAC41D6C386CCEB";
//密码登录加密数据
//unsigned char CryptDataContent[CRYPTDATA_LENTH + 1] = "ABCBB2C998FBCC38A9284DADAC4940C3A0C942A5965B9FD80BED5DF3A72B2DF83A9F807CD7D98A23"; 
//自动登录加密数据
//unsigned char CryptDataContent[CRYPTDATA_LENTH + 1] = "3F9466FD09FCF343A2EEFE35CFB8B7C607549E5FE9C85606AA5555E76BDFD57B3FA8A858A5644E4C6721A308306065DD65EEC9E15529C72456C98148BDDA14D878F4F70DF55A5033E3D55E4C1DFA9ACE87F491E6865F90CEC272E263846366987459F5A1D1DE6E0BD8DDA1315A984B301E8479D4DA6277DB619D68C16382467E01AE8BB4F368C5219E1ACFBEC31B2D5C18DD7EF3B04BA24FB02A645459823A92376B47C6FFBBA590E77D66BA0CEB254AADFB73440B5BB5A6";

//消息内容秘钥
unsigned char DeCryptKey[DECRYPT_KEY_LENTH+1] = "04501236";	//或者为//unsigned char DeCryptKey[DECRYPT_KEY_LENTH] = {0x30, 0x34, 0x35, 0x30, 0x31, 0x32, 0x33, 0x36};
//消息内容秘钥
unsigned char CryptDataContent[CRYPTDATA_LENTH + 1] = "52CF220C555202C928E868206531D380F9536E4FB249FFBDCD5DAF41A24D6721B9CC67A96AC1950CE40FB4D7BFE6B1A7B15BE9F448698408C23D4241D2BC5C1677B8FAC498DCAF55CCA008F70A3FBF9534423EF89D1070372B93BF846644AAFCFE30B5429973DC24F96E47643DCDBD5459D9008738C6B6743709FD5097F4EEEAC97039158B7AF36197B3B4C692DF3977F534D3E56E98AA983934A742EB35754DE315F596DA3A84380DD38C421E858C2B0C05BB22DFF7A5A98FC05C857EBE7ECAD8DF43B6498EEE3440E963098CEB099FD451B61460CBD44609465757482826D7390CA2BA2D60C1B997FD3FD612B5734C1337F16CBC4DA131CEC315B696E904A176549CE67949E7F552F820DC59E60597F5C8B7163B4A67A62866DF29A28D5374EB6014CDFC1C88057BCD770F11C634198D4F6A5F63F0F8BC87D3DBEF3667A8DD0E929381DC11FA0265E8A3323B046CF9EDE50F310FED892AA9ED45FA5BD1804261BA08C4DE072B42CE60F9E3512719C0F01CFD02E45DF9B0BB0B0F0A1163311B7A0760EB8368EDE487D191171FFE3E511E72276848F8D995D5F450F36CE1873745F09F46CA2ECA52BFC1B2BABBE3DF04AFF96253032A51D64E67E151DD5D299CDEB95EC0EDE6924C339A354786BD6AB5992DA6D43E6CFAE44B058BAFD4C4377514A29DB9D81892CAC61EC136B9FBEDC1EF65AD63B8A1AC4CE616683EB8FFCE7F519C2B680431A3FBBAD9C64A7082F72153DF303532B725DA95B15D9C99C095AC126796B5D8001BD50F8E4B4B5C205D763751CF191DF8CC60E5672ED593DD783CC5832408FD9A9084234C82E8BE4F7E2EB268358420B5E518DE5B639E4C421C54CD823F4204103ECFF5AD79564B00B9554FF3E889E06FF4AEE4DD531C1037100F0552A32E96A00E3045CF3D5D263604ACF15407442AB796048B4C113663920E761F0258139B5E2101BA08D1206183802556E626EABFB06F5AE82D8A2F40D31A79064847E4A644333F22E0F77974B3BACCA74FFD610CED3D463345C2C648E7FDFE4ED620D16FE6B8F7F912F8E42F12B2F182D3F792CA161CD016564C69C066B9D181D0041F3DDB92EBBF7EE788140E911942066011C31582F4DD80FA6477FEA421C390F560C5E66B93B03718604576573CC1CCFB74365E0DBFC497921BDDC4EF001039CC75D52C374312B22692257F3466BA5523425535C3B4AD7AEF739F86012D5DAD682CF140DCAD9EAD230CF9E11CE065D3C40EA2B446C2630A13064BD05CD1";

//密文十六进制字符串长度
int CryptDataLen = CRYPTDATA_LENTH;

//测试代码
int main()
{

	//为解密后的明文数据申请空间
	//原始密文为十六进制字符串，转换成二进制后长度为原来的二分之一	
	unsigned char *DeCryptData = new unsigned char[CRYPTDATA_LENTH/2];

	if (DeCryptData == NULL)
	{
		cout<<"=============申请内存空间失败=============="<<endl;
		return -1;
	}
	
	//申请的内存初始化
	memset(DeCryptData, 0 , CRYPTDATA_LENTH/2);
	
	//原始密文数十六进制字符串转换为二进制字节数据
	/*if(!hex2byte(CryptDataContent, CryptDataLen))
	{
		cout<<"============hex2byte 失败 =============="<<endl;	
	}*/

	UUPT_DECRYPT_ARG_S  data;
	data.pSrc = CryptDataContent;
	data.nSrcLen = CryptDataLen;
	data.pKey = DeCryptKey;
	data.nKeyLen = DECRYPT_KEY_LENTH;
	data.pDst = DeCryptData;
	data.nDstLen = CRYPTDATA_LENTH/2;
		
	//调用解密接口
	if(!UUPT_Decrypt(&data))
	{
		cout<<"=========解密失败==========="<<endl;
		return -1;
	}
	else
	{
		cout<<"=========解密成功==========="<<endl;
		cout<<"nOutOffset :"<<data.nOffSet<<endl;
		cout<<"nOutLen :"<<data.nDstLen<<endl;
	}
	
	char *pout = new char[data.nDstLen + 1];
	memcpy(pout, data.pDst + data.nOffSet, data.nDstLen);
	pout[data.nDstLen] = '\0';
	cout<< "DeCryptData Is :"<<pout<<endl;
	return 0;
}


 /*=======================================================================================
 * 函数名称:	UUPT_Decrypt
 * 参数信息:	arg						[IN]需要解密数据的相关信息
		arg->pSrc					[IN]密文数据的地址
		arg->nSrcLen					[IN]密文数据的长度
		arg->pKey					[IN]密钥数据的地址
		arg->nKeyLen					[IN]密钥数据的地址
		arg->nInType					[IN]密文数据类型
								 
 * 函数返回:	true:						[OUT]解密成功
 		false: 						[OUT]解密失败
		arg->pDst					[OUT]解密后明文数据的地址
		arg->nDstLen					[OUT]解密后明文数据有效信息长度，其长度<  解密后数据的总长度)
		arg- >nOffset					[OUT]解密后明文数据有效信息距离起始地址的偏移量			 
 * 函数功能:	uu跑腿协议加密数据解密
 * 创建日期:	2016-12-01
 * 创建人员:	gpengyuan
 =======================================================================================*/
 bool UUPT_Decrypt(UUPT_DECRYPT_ARG_S *arg)
 {

	/*******************************************
	 *加密消息长度至少为16 字节，并且为8  的倍数
	 *密钥长度不能小于1
	********************************************/
	if(arg == NULL ||
			arg->pSrc == NULL ||
			arg->pKey == NULL ||
			arg->pDst == NULL ||
			arg->nSrcLen % 16 != 0 ||
			arg->nSrcLen < 32 ||
			arg->nSrcLen != (arg->nDstLen * 2)||
			arg->nKeyLen <= 0 )
	{
		return false;
	}

	unsigned char *pFormattedSrc = NULL;
	int nFormattedSrcLen = 0;
	int nDstTotalLen = arg->nDstLen;

	//根据密文类型(arg->nInType),	对密文数据进行转换
	switch(arg->nInType)
	{
		case UUPT_IN_HEX:
		{
			pFormattedSrc = new unsigned char [arg->nSrcLen/2 + 1];
			nFormattedSrcLen = arg->nSrcLen/2;

			if( pFormattedSrc == NULL)
			{
				return false;
			}

			if(!hex2byte(arg->pSrc, arg->nSrcLen, pFormattedSrc, nFormattedSrcLen))
			{
				goto UUPTDecryptFinal;
			}

			if(nFormattedSrcLen != arg->nDstLen)
			{
				goto UUPTDecryptFinal;
			}
			
			break;
		}

		default:
		{
			return false;
		}

	}
		
	for (int i = 0; i < nFormattedSrcLen; i += 8)
	{
		if(!UUPT_Decode(pFormattedSrc, nFormattedSrcLen, i, arg->pKey, arg->nKeyLen, arg->pDst, i))
		{
			goto UUPTDecryptFinal;
		}
	}

	for (int i = 8; i < nFormattedSrcLen; i++)
	{
		arg->pDst[i] = (unsigned char)(arg->pDst[i] ^ pFormattedSrc[ i - 8]);
	}


	arg->nDstLen = 0;
	arg->nOffSet = arg->pDst[0] & 0x07;
	arg->nDstLen = nFormattedSrcLen - arg->nOffSet - 10;	//明文数据长度
	arg->nOffSet += 3;	//明文数据偏移量

	if(arg->nDstLen <= 0 || (arg->nOffSet + arg->nDstLen) > nDstTotalLen)
	{
		goto UUPTDecryptFinal;
	}
	
        if(pFormattedSrc != NULL)
        {
                delete []pFormattedSrc;
                pFormattedSrc = NULL;
        }
 
	return true;	 

 UUPTDecryptFinal:
 	
 	if(pFormattedSrc != NULL)
	{
		delete []pFormattedSrc;
		pFormattedSrc = NULL;
	}

	return false;
}

 
 /*=======================================================================================
 * 函数名称:	Decode
 * 参数信息:	pIn							[IN]密文数据的地址
		nInLen							[IN]密文数据的长度
		nInPos							[IN]距离密钥数据的起始地址的偏移量
		pKey							[IN]密钥数据的地址
		nKeyLen							[IN]密钥数据的长度
									 
 * 函数返回:	true:							[OUT]转码成功
 		false: 						 	[OUT]转码失败
		pOut							[OUT]解密后明文数据的地址
		nOutPos							[OUT]解密后明文数据有效信息距离起始地址的偏移量			 
 * 函数功能:	uu	跑腿协议加密数据转发函数
 * 创建日期:	2016-12-01
 * 创建人员:	gpengyuan
 =======================================================================================*/
 bool UUPT_Decode( unsigned char *pIn,   int nInLen, int nInPos, unsigned char *pKey, int nKeylen, unsigned char *pOut,  int nOutPos)
 {
	if( pIn == NULL ||
			pKey == NULL || 
			pOut == NULL ||
			nInLen < 16 ||
			nInLen % 8 !=0 ||
			nKeylen <= 0)
	{
		return false;
	}
	  
	if (nOutPos > 0)
  	{
		for (int i = 0; i < 8; i++)
		{
			pOut[nOutPos + i] = (unsigned char)(pIn[nInPos + i] ^ pOut[nOutPos + i - 8]);          
		}
  	}
	else
	{
		memcpy(pOut, pIn, 8);
	}

    UUPT_FORMAT_KEY FormattedKey;

	if(! UUPT_FormatKey(pKey, nKeylen, FormattedKey))
	{
		return false;
	}
	
	int y = ConvertByteArrayToInt(pOut, nInLen, nOutPos);
    	int z = ConvertByteArrayToInt(pOut, nInLen, nOutPos + 4);
    	int sum = 159984;
    	int delta = 9999;
    	int n = 16;

    	while (n-- > 0)
    	{
        	z -= ((y << 4) + FormattedKey.Key3 ^ y + sum ^ (y >> 5) + FormattedKey.Key4);
     	 	y -= ((z << 4) + FormattedKey.Key1 ^ z + sum ^ (z >> 5) +  FormattedKey.Key2);
        	sum -= delta;
    	}

	int a = ConvertIntToByteArray(y);
	int b = ConvertIntToByteArray(z);
	memcpy(pOut + nOutPos,  (unsigned char *)(&a), 4);
	memcpy(pOut + nOutPos + 4, (unsigned char *)(&b), 4);

	return true;
 }


/*=======================================================================================
* 函数名称:	FormatKey
		pKey 						   	[IN]密钥数据的地址
		nKeyLen						   	[IN]密钥数据的长度
									
* 函数返回:    	true:						  	[OUT]转码成功
		false:						  	[OUT]转码失败
		DstFormatKey				  		[OUT]转码后的密钥
* 函数功能:    	密钥转码
* 创建日期:    	2016-12-01
* 创建人员:    	gpengyuan
=======================================================================================*/

bool UUPT_FormatKey(unsigned char *pKey, int nKeylen, UUPT_FORMAT_KEY &DstFormatKey)
{
	
	if ( pKey == NULL || nKeylen <= 0)
   	{
		return false;
   	}
	
	unsigned char RefineKey[KEY_LENTH] = {0};

	if(nKeylen > KEY_LENTH)
	{
		memcpy(RefineKey, pKey, KEY_LENTH);
	}
	else
	{	
		memcpy(RefineKey, pKey, nKeylen);

		for (int i = nKeylen; i < 16; i++)
        {
          	  	RefineKey[i] = 0x20;
       	}
	}
	
	DstFormatKey.Key1 = ConvertByteArrayToInt(RefineKey, KEY_LENTH, 0);
	DstFormatKey.Key2 = ConvertByteArrayToInt(RefineKey, KEY_LENTH, 4);	
	DstFormatKey.Key3 = ConvertByteArrayToInt(RefineKey, KEY_LENTH, 8);
	DstFormatKey.Key4 = ConvertByteArrayToInt(RefineKey, KEY_LENTH, 12);

	return  true;
}


int ConvertIntToByteArray(int nInt)
{
	int result = 0;
	result = (int)ntohl(nInt);
	return result;
}

 int ConvertByteArrayToInt(unsigned char *pByteArray, int nByteArrayLen,  int nOffset)
 {
	if (nOffset + 4 > nByteArrayLen)
	{
		return 0;
	}

	int nOut =0;
	int nTmp = *(int *)(pByteArray + nOffset);
	nOut = (int)ntohl(nTmp);
	return nOut;
 }

 int hex2int(char ch)
 {
	 if(ch >='0' && ch <= '9')
		 return ch -'0';
	 if(ch >='A' && ch <= 'F')
		 return ch + 10 - 'A';
	 if(ch >='a' && ch <= 'f')
		 return ch + 10 - 'f';
	 return 0;
 }
 
 bool is_hex(char ch)
 {
	 return (ch >='0' && ch <= '9') || 
		 (ch >='A' && ch <= 'F') || 
		 (ch >='a' && ch <= 'f');
 }
 
 bool hex2byte(unsigned char *pHex, int nHexLen, unsigned char *pByte, int &nByteLen)
 {
	 if(pHex == NULL || 
	 		nHexLen <= 0 || 
	 		nHexLen % 2 != 0 ||
	 		pByte == NULL ||
	 		nByteLen != nHexLen/2 )
	 {
		 return false;
	 }
	 
	 int i = 0;
 
	 for(i = 0;i < nHexLen;i++)
	 {
		 if(!is_hex(pHex[i]))
		 {
			 return false;
		 }
	 }
 
	 for(i = 0;i < nHexLen;i += 2)
	 {
		 pByte[i/2] = (hex2int(pHex[i]) << 4) + hex2int(pHex[i + 1]);
	 }

	 nByteLen = nHexLen/2;
	 pByte[nByteLen] = '\0';
	 
	 return true;
 }

 
 
