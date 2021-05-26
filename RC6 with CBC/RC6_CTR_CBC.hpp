#ifndef RC6_CTR_CBC_HPP_INCLUDED
#define RC6_CTR_CBC_HPP_INCLUDED

#include<bits/stdc++.h>
using namespace std;

#define w 32  //规定一字的位数 1 word = 32 bits = 4 bytes
#define r 20
#define b 16  // b bytes = b/bytes words
#define t (2*r+4)
#define bytes (w / 8)
#define c ((b + bytes - 1) / bytes)
#define ROTL(x, y) (((x) << (y & (w - 1))) | ((x) >> (w - (y & (w - 1)))))
#define ROTR(x, y) (((x) >> (y & (w - 1))) | ((x) << (w - (y & (w - 1)))))

typedef unsigned int Word;
const int INF = 63557;//无穷大
unsigned char CounTer[INF][b] = {0};
//unsigned char Key[b];//= {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
unsigned char CTR_ciphertext[INF][b]={0};
unsigned char CBC_IV[b];


Word lgw=log2(w);
Word S[t];
Word P;
Word Q;
/***************************
对于给定的参数r和w，初始化参数
Pw = Odd((e-2)2w)； Qw = Odd((𝜙-1)2w)
这里 e = 2.718281828459…（自然对数的底）；𝜙 = 1.618033988749…（黄金分割比例）
****************************/

unsigned char Key[b];//= {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
unsigned char plaintext[3][b]={{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                                {0x02, 0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8a, 0x9b, 0xac, 0xbd, 0xce, 0xdf, 0xe0, 0xf1},
                                {0x02, 0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8a, 0x9b, 0xac, 0xbd, 0xce, 0xdf, 0xe0, 0xf1}};
unsigned char ciphertext[INF][b]={0};

void Generate_Key(unsigned char* Key)
{
    time_t _;
    srand((unsigned) time(&_));
    for(int i=0; i<b; i++)
    {
        Word keys=rand()%256;
        Key[i]=keys;
    }
}

void Generate_CBC_IV(unsigned char* CBC_IV)
{
    time_t _;
    srand((unsigned) time(&_));
    //生成nonce
    for(int i=0; i<b; i++)
    {
        Word IV=rand()%256;
        CBC_IV[i]=IV;
    }
}


void Generate_CounTer_IV(unsigned char* CounTer)
{
    time_t _;
    srand((unsigned) time(&_));
    //生成nonce
    for(int i=0; i<b/2; i++)
    {
        Word IV=rand()%256;
        CounTer[i]=IV;
    }
}


void RC6_Constraints(Word &p,Word &q)
{
    p = (Word)ceil(((M_E - 2) * pow(2, w)));             // e
    q = (Word)((1.618033988749895 - 1) * pow(2, w));    // Golden Ratio
}

//密钥扩展
void RC6_Key_Schedule(unsigned char *K)
{
    Word L[c]; /* Big enough for max b */
    L[c - 1] = 0;
    for (int i = b - 1; i >= 0; i--)
        L[i / bytes] = (L[i / bytes] << 8) + K[i]; //little edian 小端存储 + char =1 bytes = 8 bits 向左移位8 加上Key[i]
    /*****************************************
    these key bytes are then
    loaded in little-endian fashion into an array of c w-bit words L[0]; : : :; L[c 􀀀 1].
    Thus the first byte of key is stored as the low-order byte of L[0], etc.,
    *****************************************/
    S[0] = P;
    for (int i = 1; i <= 2 * r + 3; i++)
        S[i] = S[i - 1] + Q;
        //对 i = 1 至 t-1，S[i] = S[i-1] + Qw其中t=2r+2，加法是模 2w 的加法运算
    Word A = 0;
    Word B = 0;
    Word i = 0;
    Word j = 0;
    Word v;
    if(c>2*r+4)
        v=c;
    else v=2*r+4;
    for (int temp = 1; temp <= 3*v; temp++)
    {
        A = S[i] = ROTL(S[i] + A + B, 3);
        B = L[j] = ROTL(L[j] + A + B, A + B);
        i = (i + 1) % t;
        j = (j + 1) % c;
    }
}

void RC6_Encrypt(unsigned char* plaintext,unsigned char* ciphertext)
{
    Word A,B,C,D;
    Word temp[c];
    for(int i=0; i<c; i++)
        temp[i]=plaintext[i*4]+(plaintext[i*4+1]<<8)+(plaintext[i*4+2]<<16)+(plaintext[i*4+3]<<24);
    /******************************************************************************
    LSB 2^0
    The firstbyte of plaintext or ciphertext is placed in the least-significant byte of A; the
    last byte of plaintext or ciphertext is placed into the most-significant byte of D.
    We use (A;B;C;D) = (B;C;D;A) to mean the parallel assignment of values
    on the right to registers on the left.
    故明文从右往左存储
    ******************************************************************************/
    A=temp[0];
    B=temp[1];
    C=temp[2];
    D=temp[3];
    B+=S[0];
    D+=S[1];
    for(int i=2; i<=2*r; i+=2)
    {
        Word temp_B = ROTL(B * (2 * B + 1), lgw);
        Word temp_D = ROTL(D * (2 * D + 1), lgw);
        A = ROTL(A ^ temp_B, temp_D) + S[i];
        C = ROTL(C ^ temp_D, temp_B) + S[i + 1];
        Word temp_A = A;
        A = B;
        B = C;
        C = D;
        D = temp_A;
    }
    A+=S[2*r+2];
    C+=S[2*r+3];
    temp[0] = A;
    temp[1] = B;
    temp[2] = C;
    temp[3] = D;
    for (int i = 0; i < c; i++)
    {
        ciphertext[4 * i] = temp[i] & 0xFF;
        ciphertext[4 * i + 1] = (temp[i] >> 8) & 0xFF;
        ciphertext[4 * i + 2] = (temp[i] >> 16) & 0xFF;
        ciphertext[4 * i + 3] = (temp[i] >> 24) & 0xFF;
    }
}

void RC6_Decrypt(unsigned char* ciphertext,unsigned char* plaintext)
{
    Word A,B,C,D;
    Word temp[4];
    for(int i=0; i<c; i++)
        temp[i]=ciphertext[i*4]+(ciphertext[i*4+1]<<8)+(ciphertext[i*4+2]<<16)+(ciphertext[i*4+3]<<24);
    A=temp[0];
    B=temp[1];
    C=temp[2];
    D=temp[3];
    C-= S[2 * r + 3];
    A-= S[2 * r + 2];
    for (int i = 2 * r; i >= 2; i -= 2)
    {
        Word temp_D = D;
        D = C;
        C = B;
        B = A;
        A = temp_D;
        temp_D = ROTL(D * (2 * D + 1), lgw);
        Word temp_B = ROTL(B * (2 * B + 1), lgw);
        C = ROTR(C - S[i + 1], temp_B) ^ temp_D;
        A = ROTR(A - S[i], temp_D) ^ temp_B;
    }
    D -= S[1];
    B -= S[0];
    temp[0] = A;
    temp[1] = B;
    temp[2] = C;
    temp[3] = D;
    for (int i = 0; i < c; i++)
    {
        plaintext[4 * i] = temp[i] & 0xFF;
        plaintext[4 * i + 1] = (temp[i] >> 8) & 0xFF;
        plaintext[4 * i + 2] = (temp[i] >> 16) & 0xFF;
        plaintext[4 * i + 3] = (temp[i] >> 24) & 0xFF;
    }
}


void CTR_RC6_Encrypt(unsigned char* plaintext,unsigned char* ciphertext)
{
    static Word last_num = b-1;//计数器+1在CounTer中的组号
    static Word first_num = 0;
    CounTer[first_num][last_num]+=1;
    memcpy(CounTer[first_num+1],CounTer[first_num],b);
    if((Word)CounTer[first_num][last_num]==255)
        last_num--;
    RC6_Encrypt(CounTer[first_num],ciphertext);
    memcpy(CTR_ciphertext[first_num],ciphertext,b);
    for(int i=0; i<b; i++)
        ciphertext[i]=ciphertext[i]^plaintext[i];
    first_num++;
}

void CTR_RC6_Decrypt(unsigned char* ciphertext,unsigned char* plaintext,int num)
{
    /*for(int i=0;i<b;i++)
        cout<<hex<<(Word)CounTer[num][i]<<" ";
    cout<<endl;*/
    for(int i=0; i<b; i++)
            plaintext[i]=CTR_ciphertext[num][i]^ciphertext[i];
}

void RC6_CBC_Encrypt(unsigned char* plaintext, unsigned char* ciphertext, unsigned char* CBC_IV)
{
    //RC6_CBC模式下 ciphertext[0]用来存储IV
    for(int i=0;i<b;i++)
    {
        plaintext[i]= CBC_IV[i]^plaintext[i];
    }
    RC6_Encrypt(plaintext,ciphertext);
}

void RC6_CBC_Decrypt(unsigned char* ciphertext, unsigned char* plaintext, unsigned char* CBC_IV)
{
    RC6_Decrypt(ciphertext,plaintext);
    for(int i=0;i<b;i++)
        plaintext[i]=plaintext[i]^CBC_IV[i];
}



#endif // RC6_CTR_CBC_HPP_INCLUDED
