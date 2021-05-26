#include<bits/stdc++.h>
#include<windows.h>
#include "MD5.hpp"
#include "RC6_CTR_CBC.hpp"
using namespace std;

bitset<128> charToBitset(unsigned char s[32])
{
	bitset<128> bits;
	for(int i=0; i<16; ++i)
    {
		if(isdigit(s[2*i])) s[2*i] = s[2*i]-'0';
        if(isalpha(s[2*i])) s[2*i] = s[2*i]-'a'+10;
        if(isdigit(s[2*i+1])) s[2*i+1] = s[2*i+1]-'0';
        if(isalpha(s[2*i+1])) s[2*i+1] = s[2*i+1]-'a'+10;
        s[i] = (Word) s[2*i]*16 + (Word) s[2*i+1];
		for(int j=0; j<8; ++j)
			bits[i*8+j] = ((s[i]>>j) & 1);
    }
	return bits;
}

int main()
{

    RC6_Constraints(P,Q);
    RC6_Key_Schedule(Key);
    Generate_CounTer_IV(CounTer[0]);
    Generate_CBC_IV(CBC_IV);
    Generate_Key(Key);
    int num= sizeof(plaintext)/b;

    cout<<"Do u want to use hash function to generate your keys ? y/n"<<endl;
    char ch = cin.get();
    cin.get();
    if(ch=='y')
    {
        cout<<"Please enter your password.(such as ""Wubalubadubdub"")"<<endl;
        string digest;
        getline(cin,digest);
        digest = getMD5Code(digest);
        cout<<digest<<endl;
        cout<<"Please keep your password in mind."<<endl;
        fstream file1;
        file1.open("C:\\Users\\87229\\Desktop\\Key.txt", ios::binary | ios::out);
        bitset<8*b> buffer;
        buffer = charToBitset((unsigned char*)digest.c_str());
        file1.write((char*)&buffer,sizeof(buffer));
        file1.close();
    }
    else
    {
        cout<<"Or do u want to generate your keys ramdomly ? y/n"<<endl;
        char ch1 = cin.get();
        cin.get();
        if(ch1=='y')
        {
            bool ok = true;
            while(ok)
            {
            Generate_Key(Key);
            for(int i=0;i<b;i++)
                cout<<hex<<(Word)(unsigned char)Key[i]<<" ";
            cout<<endl;
            cout<<"Here is your keys ! Do u want to regenerate them ? y/n"<<endl;
            char ch2 = cin.get();
            cin.get();
            if(ch2 == 'n')
            {
                fstream file1;
                file1.open("C:\\Users\\87229\\Desktop\\Key.txt", ios::binary | ios::out);
                file1.write((char*)Key,sizeof(Key));
                file1.close();
                ok = false;
            }
            }
        }
        else
        {
            cout<<"Please enter your keys by manually typing in hex.(like 0f 0d 16 a2 f9 35 2d ee 9f e6 73 53 08 19 cb b8)"<<endl;
            string keys;
            getline(cin,keys);
            keys.erase(remove(keys.begin(), keys.end(), ' '), keys.end());
            cout<<keys<<endl;
            fstream file1;
            file1.open("C:\\Users\\87229\\Desktop\\Key.txt", ios::binary | ios::out);
            bitset<8*b> buffer;
            buffer = charToBitset((unsigned char*)keys.c_str());
            file1.write((char*)&buffer,sizeof(buffer));
            file1.close();
        }
    }


   /* fstream file1;
	file1.open("C:\\Users\\87229\\Desktop\\Key.txt", ios::binary | ios::out);
	bitset<8*b> buffer;
	buffer = charToBitset(Key);
	file1.write((char*)&buffer,sizeof(buffer));
	file1.close();*/

    fstream file1;
    char temp[b];
	file1.open("C:\\Users\\87229\\Desktop\\Key.txt", ios::binary | ios::in);
	file1.read(temp, sizeof(temp));
	file1.close();
    cout<<"Now generated keys are as follows:"<<endl;
    for(int i=0;i<b;i++)
        cout<<hex<<(Word)(unsigned char)temp[i]<<" ";
    cout<<endl;
    Sleep(500);
    cout<<"And keys are saved in C:\\Users\\87229\\Desktop\\Key.txt"<<endl;
    Sleep(300);

    //读取明文plaintext.txt
    ifstream in;
	ofstream out;
	in.open("C:\\Users\\87229\\Desktop\\plaintext.txt", ios::in | ios::binary);
	out.open("C:\\Users\\87229\\Desktop\\ciphertext.txt", ios::out| ios::binary);
	in.seekg(0, in.end);   //追溯到流的尾部
    int length = in.tellg();  //获取流的长度
    in.seekg(0, in.beg);  //回到流的头部
	//cout<<length<<endl;
	//unsigned char plain[b];
	int groups = ceil(length*1.0/b);
	length = groups*b;

	char* plain = new char[length]();
	//memset(plain,0,sizeof(plain));
	memcpy(ciphertext[0],CBC_IV,b);
	if (in.is_open()) {
		cout << "Now reading plaintext.txt......" << endl;
		in.read(plain, length);    //read函数
        //int readingbytes = in.gcount();
        //cout<<readingbytes<<endl;
	}
	Sleep(500);
	cout<<"Reading complete!"<<endl;
	Sleep(300);
	cout<<"Now writing into ciphertext.txt......"<<endl;
	Sleep(500);
	unsigned char IV[b];
	memcpy(IV,CBC_IV,b);
	for(int i=0;i<groups;i++)
	{
	    static int j=0;
	    char temp[b];
	    static unsigned char ciphertext[b];
	    memcpy(temp,plain+i*b,b);
        RC6_CBC_Encrypt((unsigned char*)temp,ciphertext,IV);
        out.write((char*)ciphertext,b);
        memcpy(IV,ciphertext,b);
        j++;
	}
	in.close();
	out.close();
	delete[] plain;
	cout<<"Writing complete!"<<endl;
	Sleep(300);
	cout<<"Please check ciphertext.txt!"<<endl;
	Sleep(500);

	// 解密 ciphertext.txt，并写入confirm plaintext.txt
	in.open("C:\\Users\\87229\\Desktop\\ciphertext.txt",ios::in | ios::binary);
	out.open("C:\\Users\\87229\\Desktop\\confirm plaintext.txt", ios::out| ios::binary);
	char* cipher = new char [length]();
	if (in.is_open()) {
		cout << "Now reading ciphertext.txt......" << endl;
		in.read(cipher, length);    //read函数
        //int readingbytes = in.gcount();
        //cout<<readingbytes<<endl;
	}
	Sleep(500);
	cout<<"Reading complete!"<<endl;
	Sleep(300);
	cout<<"Now writing into confirm plaintext.txt......"<<endl;
	Sleep(500);
	memcpy(IV,CBC_IV,b);
	for(int i=0;i<groups;i++)
	{
	    static int j=0;
	    char temp[b];
	    unsigned char plain[b];
	    memcpy((unsigned char*)temp,cipher+i*b,b);
        RC6_CBC_Decrypt((unsigned char*)temp,plain,IV);
        out.write((char*)plain,b);
        memcpy(IV,temp,b);
        j++;
	}
	in.close();
	out.close();
    delete[] cipher;
    cout<<"Writing complete!"<<endl;
	Sleep(300);
	cout<<"Please check confirm plaintext.txt!"<<endl;
    /*********************RC6 Encrypt**************/
/*
    cout<<"RC6_Encrypt:"<<"Here are ciphertexts"<<endl;
    for(int i=0;i<num;i++)
        RC6_Encrypt(plaintext[i],ciphertext[i]);
    for(int i=0;i<num;i++)
    {
        for(int j=0;j<b;j++)
            cout<<hex<<(Word)ciphertext[i][j]<<" ";
        cout<<endl;
    }
    cout<<"RC6_Decrypt:"<<"Here are plaintexts"<<endl;
    for(int i=0;i<num;i++)
        RC6_Decrypt(ciphertext[i],plaintext[i]);
    for(int i=0;i<num;i++)
    {
        for(int j=0;j<b;j++)
            cout<<hex<<(Word)plaintext[i][j]<<" ";
        cout<<endl;
    }
    ciphertext[INF][b]={0};

    /*********************************************/


    /*********************RC6-CTR Encrypt*********/
/*
    cout<<"RC6_CTR_Encrypt:"<<"Here are ciphertexts"<<endl;
    for(int i=0;i<num;i++)
            CTR_RC6_Encrypt(plaintext[i],ciphertext[i]);
    //b=16
    for(int i=0;i<num;i++)
    {
        for(int j=0;j<b;j++)
            cout<<hex<<(Word)ciphertext[i][j]<<" ";
        cout<<endl;
    }
    for(int i=0;i<num;i++)
            CTR_RC6_Decrypt(ciphertext[i],plaintext[i],i);

   cout<<"RC6_CTR_Decrypt:"<<"Here are plaintexts"<<endl;
    for(int i=0;i<num;i++)
    {
        for(int j=0;j<b;j++)
            cout<<hex<<(Word)plaintext[i][j]<<" ";
        cout<<endl;
    }
    /**********************************************/

    /***************RC6_CTR 文件写入加密*******************/
/*
    //CTR_RC6_Encrypt(plaintext[0],ciphertext[0],1);
    //cout<<plaintext[0]<<endl;
    for(int i=0;i<b;i++)
        cout<<hex<<(Word)ciphertext[0][i]<<" ";
    cout<<endl;
	fstream file1;
	file1.open("D://a.txt", ios::binary | ios::out|ios::trunc);
	char buffer[b];
	memcpy(buffer,ciphertext[0],b);
	//buffer=charToBitset(ciphertext[0]);
    file1.write(buffer,sizeof(buffer));
	file1.close();
    /*for(int i=0; i<b; i++)
        cout<<hex<<(Word)(unsigned char)buffer[i]<<" ";
	cout<<endl;*/
	//cout<<(unsigned char*)buffer<<endl;
    // 读文件 a.txt
/*
	char temp[b];
	file1.open("D:\\a.txt", ios::binary | ios::in);
	file1.read(temp, sizeof(temp));
	file1.close();
      for(int i=0;i<b;i++)
        cout<<hex<<(Word)(unsigned char)temp[i]<<" ";
    cout<<endl;
    /*for(int i=0; i<b; i++)
        cout<<hex<<(Word)(unsigned char)temp[i]<<" ";
    cout<<endl;*/
	// 解密，并写入文件 cipher.txt
/*
    CTR_RC6_Decrypt((unsigned char*)temp,plaintext[0],0);
    bitset<128> temp_text;
    /*for(int i=0;i<b;i++)
        cout<<hex<<(Word)plaintext[0][i]<<" ";
    temp_text=charToBitset(plaintext[0]);
	file1.open("D:\\b.txt", ios::binary | ios::out|ios::trunc);
	file1.write((char*)&temp_text,sizeof(temp_text));
	file1.close();
    //cout<<(unsigned char*) temp_text<<endl;
    for(int i=0; i<b; i++)
        cout<<hex<<(Word)(unsigned char)temp_text[i]<<" ";


    /************************************************/

    /*******************RC6_CTR 对图片加密解密***************/
/*
	ifstream in;
	ofstream out;
	in.open("D:\\test.bmp", ios::binary);
	out.open("D:\\cipher.txt", ios::binary);
	char plain[b];
	while(in.read(plain, sizeof(plain)))
	{
		char cipher[b];
		CTR_RC6_Encrypt((unsigned char*)plain,(unsigned char*)cipher);
		out.write(cipher, sizeof(cipher));
		memset(cipher,0,sizeof(cipher));  // 置0
	}
	in.close();
	out.close();

	// 解密 cipher.txt，并写入图片 test1.bmp
	in.open("D:\\cipher.txt", ios::binary);
	out.open("D:\\test1.bmp", ios::binary);
	memset(plain,0,sizeof(plain));
	while(in.read(plain, sizeof(plain)))
	{
		static int i=0;
		char temp[b];
		CTR_RC6_Decrypt((unsigned char*)plain,(unsigned char*)temp,i);
        out.write(temp, sizeof(temp));
		memset(temp,0,sizeof(temp)); // 置0
		i++;
	}
	in.close();
	out.close();

    /*************************************************/

    /*****************RC6_CBC Encrypt*******************/
/*
    memcpy(ciphertext[0],CBC_IV,b);
    for(int i=0;i<num;i++)
        RC6_CBC_Encrypt(plaintext[i],ciphertext[i+1],ciphertext[i]);
    for(int i=1;i<=num;i++)
    {
        for(int j=0;j<b;j++)
            cout<<hex<<(Word)ciphertext[i][j]<<" ";
        cout<<endl;
    }
    for(int i=0;i<num;i++)
        RC6_CBC_Decrypt(ciphertext[i+1],plaintext[i],ciphertext[i]);
    for(int i=0;i<num;i++)
    {
        for(int j=0;j<b;j++)
            cout<<hex<<(Word)plaintext[i][j]<<" ";
        cout<<endl;
    }

    /**************************************************/

    return 0;
}
