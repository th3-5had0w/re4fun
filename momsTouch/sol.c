// gcc sol.c -o sol1 -m32

#include <stdlib.h>
#include <stdio.h>

int arr1[] = {0x39,
0xb6,
0x9e,
0xa3,
0x84,
0x9f,
0xe9,
0x61,
0x7b,
0x55,
0x9,
0xd9,
0xa7,
0x98,
0x34,
0x47,
0x84,
0x95,
0x3c,
0xec,
0x5d,
0x44,
0x3f,
0xc3,
0x44,
0x5b,
0xf7,
0x8,
0xd3,
0x40,
0x9b,
0xd ,
0xf6,
0xb9,
0xb0,
0x7b,
0x5a,
0x1b,
0x5d,
0x55,
0x70,
0x66,
0x2f,
0x18,
0x7f,
0xe2,
0x60,
0x4,
0x79,
0x1c,
0x70,
0xd6,
0x61,
0xb0,
0x1a,
0xa5,
0x8b,
0x13,
0x2d,
0x5f,
0x53,
0x48,
0xeb,
0xca,
0x3,
0x1d,
0xc5,
0xdc,
0x38,
0x23,
0x32,
0xa8,
0xa ,
0x61,
0x41,
0x89,
0x44,
0x21,
0xd ,
0xbd,
0x3d,
0x7d,
0x15,
0x1e,
0xad,
0x2f,
0x44,
0x39,
0xc1,
0x71,
0x98,
0x16,
0xba,
0x5,
0x60,
0x3d,
0x22,
0x26,
0x1a,
0x5a,
0x4a,
0xcb,
0x3,
0x54,
0x2d,
0xc3,
0x5d,
0xf0,
0xe4,
0x6a,
0x2f,
0x23,
0xe7,
0xc3,
0xc0,
0x16,
0xf2,
0x5,
0x4f,
0x35,
0xf6,
0x68,
0xca,
0x31,
0x6d,
0x2b,
0xed,
0x8f,
0x51,
0x8,
0xe9,
0x1b,
0x53,
0x6c,
0xee,
0x0,
0xb0,
0x4c,
0xf0,
0x95,
0xb6,
0x9f,
0x38,
0x1f,
0x63,
0xf9,
0xb4,
0x57,
0x7e,
0x4,
0xc,
0x75,
0xeb,
0xd6,
0xa6,
0x59,
0x81,
0x94,
0x68,
0xd2,
0x1c,
0xd1,
0x6e,
0xee,
0xbe,
0x5d,
0xee,
0x6f,
0x2a,
0xe0,
0x5,
0x60,
0x80,
0x3e,
0x7f,
0xe4,
0xb7,
0xb3,
0xbb,
0x36,
0xb8,
0x47,
0x2c,
0xa4,
0x1e,
0x52,
0x7e,
0x9f,
0x67,
0x66,
0xf1,
0x3,
0x39,
0x60,
0xf2,
0xf7,
0x3e,
0xe1,
0x67,
0x68,
0xc2,
0xeb,
0x48,
0xc3,
0xa9,
0x48,
0x28,
0xe0,
0xfb,
0x63,
0x18,
0xb4,
0xaa,
0xc3,
0xd9,
0xc8,
0x16,
0xd7,
0xe7,
0x7d,
0x3e,
0xd9,
0x81,
0x77,
0xba,
0x74,
0xee,
0x78,
0x56,
0xd5,
0xe0,
0x99,
0x42,
0xa8,
0xdc,
0xeb,
0xf0,
0x5,
0xcd,
0xed,
0x68,
0x65,
0x22,
0x92,
0x29,
0x7b,
0x5b,
0xbe,
0x53,
0xc2,
0x3d,
0x12,
0x9c,
0x3e,
0x89,
0xd6};


int arr2[] = {0xba,
0x1c,
0x4,
0xf8,
0x3b,
0xa8,
0x9c,
0x7c,
0x8e,
0x98,
0x81,
0x89,
0x9,
0x55,
0xd0,
0xee,
0xc5,
0xfd,
0x47,
0x50,
0xa2,
0x46,
0xdf,
0x63,
0x2e,
0x51,
0x38,
0xfe,
0x6a,
0xf2,
0xa0,
0x5a,
0x94,
0xe5,
0x49,
0x62,
0x37,
0x1f,
0x79,
0xd8,
0x54,
0x1c,
0xe5,
0x68,
0xbb,
0xf0,
0x60,
0x64,
0xf,
0x49,
0xcd,
0x7d,
0xa9,
0xfd,
0x2,
0x7d,
0xca,
0x3,
0x32,
0x80,
0xc5,
0x4b,
0x3d,
0xe9,
0x74,
0x8d,
0x3d,
0x8a,
0x2c,
0xb2,
0x30,
0x78,
0xc4,
0x0};

int main()
{
	int v2, v3, v4, v5, v6;
	srand(0xff);
	for (int i=0;i<257;++i){
		rand();
	}

	for (int i=0;i<0x49;++i)
	{
		v3 = rand();
			v2 = (((arr1[i] * 16)) | (arr1[i] >> 4)) & 0xff;
			v4 = 4*(v3+v3/255);
			v5 = (v3%255)>>2;
			v6 = (v4 | v5) & 0xff;
			printf("%c", arr1[v6] ^ arr1[v2] ^ arr2[i]);
	}
}
