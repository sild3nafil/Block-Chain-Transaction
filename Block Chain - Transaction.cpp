#include <bits/stdc++.h>
#define ll unsigned long long 
using namespace std;

string LongToString(ll);
ll StringToLong(string);
string Sum(string, string);

string _strings[100]; // define max string  
int s_num;
void split (string str, char seperator)  
{  
    int currIndex = 0, i = 0;  
    int startIndex = 0, endIndex = 0;  
    while (i <= str.length())  
    {  
        if (str[i] == seperator || i == str.length())  
        {  
            endIndex = i;  
            string subStr = "";  
            subStr.append(str, startIndex, endIndex - startIndex);  
            _strings[currIndex] = subStr;  
            s_num = currIndex + 1;
            currIndex += 1;  
            startIndex = endIndex + 1;  
        }  
        i++;  
    }     
}

class SHA256
{
	protected:
		typedef unsigned char uint8;
   	 	typedef unsigned int uint32;
    	typedef unsigned long long uint64;
 
    	const static uint32 sha256_k[];
    	static const unsigned int SHA224_256_BLOCK_SIZE = (512/8);
	public:
    	void init();
    	void update(const unsigned char *message, unsigned int len);
    	void final(unsigned char *digest);
    	static const unsigned int DIGEST_SIZE = ( 256 / 8);
 
	protected:
   	 	void transform(const unsigned char *message, unsigned int block_nb);
    	unsigned int m_tot_len;
    	unsigned int m_len;
    	unsigned char m_block[2*SHA224_256_BLOCK_SIZE];
    	uint32 m_h[8];
};

string sha256(std::string input);
 
#define SHA2_SHFR(x, n)    (x >> n)
#define SHA2_ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define SHA2_ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define SHA2_CH(x, y, z)  ((x & y) ^ (~x & z))
#define SHA2_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA256_F1(x) (SHA2_ROTR(x,  2) ^ SHA2_ROTR(x, 13) ^ SHA2_ROTR(x, 22))
#define SHA256_F2(x) (SHA2_ROTR(x,  6) ^ SHA2_ROTR(x, 11) ^ SHA2_ROTR(x, 25))
#define SHA256_F3(x) (SHA2_ROTR(x,  7) ^ SHA2_ROTR(x, 18) ^ SHA2_SHFR(x,  3))
#define SHA256_F4(x) (SHA2_ROTR(x, 17) ^ SHA2_ROTR(x, 19) ^ SHA2_SHFR(x, 10))
#define SHA2_UNPACK32(x, str)                 \
{                                             \
    *((str) + 3) = (uint8) ((x)      );       \
    *((str) + 2) = (uint8) ((x) >>  8);       \
    *((str) + 1) = (uint8) ((x) >> 16);       \
    *((str) + 0) = (uint8) ((x) >> 24);       \
}
#define SHA2_PACK32(str, x)                   \
{                                             \
    *(x) =   ((uint32) *((str) + 3)      )    \
           | ((uint32) *((str) + 2) <<  8)    \
           | ((uint32) *((str) + 1) << 16)    \
           | ((uint32) *((str) + 0) << 24);   \
}
const unsigned int SHA256::sha256_k[64] = //UL = uint32
            {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
             0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
             0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
             0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
             0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
             0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
             0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
             0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
             0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
             0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
             0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
             0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
             0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
             0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
 
void SHA256::transform(const unsigned char *message, unsigned int block_nb)
{
    uint32 w[64];
    uint32 wv[8];
    uint32 t1, t2;
    const unsigned char *sub_block;
    int i;
    int j;
    for (i = 0; i < (int) block_nb; i++) {
        sub_block = message + (i << 6);
        for (j = 0; j < 16; j++) {
            SHA2_PACK32(&sub_block[j << 2], &w[j]);
        }
        for (j = 16; j < 64; j++) {
            w[j] =  SHA256_F4(w[j -  2]) + w[j -  7] + SHA256_F3(w[j - 15]) + w[j - 16];
        }
        for (j = 0; j < 8; j++) {
            wv[j] = m_h[j];
        }
        for (j = 0; j < 64; j++) {
            t1 = wv[7] + SHA256_F2(wv[4]) + SHA2_CH(wv[4], wv[5], wv[6])
                + sha256_k[j] + w[j];
            t2 = SHA256_F1(wv[0]) + SHA2_MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }
        for (j = 0; j < 8; j++) {
            m_h[j] += wv[j];
        }
    }
}
 
void SHA256::init()
{
    m_h[0] = 0x6a09e667;
    m_h[1] = 0xbb67ae85;
    m_h[2] = 0x3c6ef372;
    m_h[3] = 0xa54ff53a;
    m_h[4] = 0x510e527f;
    m_h[5] = 0x9b05688c;
    m_h[6] = 0x1f83d9ab;
    m_h[7] = 0x5be0cd19;
    m_len = 0;
    m_tot_len = 0;
}
 
void SHA256::update(const unsigned char *message, unsigned int len)
{
    unsigned int block_nb;
    unsigned int new_len, rem_len, tmp_len;
    const unsigned char *shifted_message;
    tmp_len = SHA224_256_BLOCK_SIZE - m_len;
    rem_len = len < tmp_len ? len : tmp_len;
    memcpy(&m_block[m_len], message, rem_len);
    if (m_len + len < SHA224_256_BLOCK_SIZE) {
        m_len += len;
        return;
    }
    new_len = len - rem_len;
    block_nb = new_len / SHA224_256_BLOCK_SIZE;
    shifted_message = message + rem_len;
    transform(m_block, 1);
    transform(shifted_message, block_nb);
    rem_len = new_len % SHA224_256_BLOCK_SIZE;
    memcpy(m_block, &shifted_message[block_nb << 6], rem_len);
    m_len = rem_len;
    m_tot_len += (block_nb + 1) << 6;
}
 
void SHA256::final(unsigned char *digest)
{
    unsigned int block_nb;
    unsigned int pm_len;
    unsigned int len_b;
    int i;
    block_nb = (1 + ((SHA224_256_BLOCK_SIZE - 9)
                     < (m_len % SHA224_256_BLOCK_SIZE)));
    len_b = (m_tot_len + m_len) << 3;
    pm_len = block_nb << 6;
    memset(m_block + m_len, 0, pm_len - m_len);
    m_block[m_len] = 0x80;
    SHA2_UNPACK32(len_b, m_block + pm_len - 4);
    transform(m_block, block_nb);
    for (i = 0 ; i < 8; i++) {
        SHA2_UNPACK32(m_h[i], &digest[i << 2]);
    }
}
 
string sha256(string input)
{
    unsigned char digest[SHA256::DIGEST_SIZE];
    memset(digest,0,SHA256::DIGEST_SIZE);
 
    SHA256 ctx = SHA256();
    ctx.init();
    ctx.update( (unsigned char*)input.c_str(), input.length());
    ctx.final(digest);
 
    char buf[2*SHA256::DIGEST_SIZE+1];
    buf[2*SHA256::DIGEST_SIZE] = 0;
    for (int i = 0; i < SHA256::DIGEST_SIZE; i++)
        sprintf(buf+i*2, "%02x", digest[i]);
    return std::string(buf);
}

int main()
{
	string line, transaction[3], second_nonce, third_nonce, key;
	int i=0;

	while(getline(cin, line))
	{
    	if (line.empty())
		{
			break;
    	}
    	else
    	{
			if(i==0)
				transaction[0] = line;
			else if(i==1)
				split(line,'_');
			else if(i==2)
				second_nonce = line;
			else if(i==3)
				transaction[2] = line;
			else if(i==4)
				key = line;
				
			i++;
    	}
	}
	
	string money_guess = "1";
	bool true_money = false;
	
	string nonce = "1", previous_hash = "0000000000000000000000000000000000000000000000000000000000000000";
	int index = 1;
	
	while (1)
	{
		string hash_n = "1";
		hash_n.append(nonce);
		hash_n.append(transaction[0]);
		hash_n.append(previous_hash);
		
		string target_hash = sha256(hash_n);
		//cout<<target_hash<<endl;
		if (target_hash[0] == '0' && target_hash[1] == '0' && target_hash[2] == '0' && target_hash[3] == '0') //target_hash[:prefixed] == '0'*prefixed:  //檢查是否符合條件
      	{
		  	previous_hash = target_hash;
		  	//cout<<previous_hash<<endl; 			
		  	nonce = "1";
			index++;
			break;
      	}
      	  			
    	else
       		nonce = Sum(nonce, "1");       //不符合條件則nonce+1
	}
	
	string first_block_hash = previous_hash;
	while(!true_money)
	{
		//cout<<"#"<<money_guess<<endl;
		
		transaction[1] = _strings[0];
		transaction[1].append(money_guess);
		transaction[1].append(_strings[1]);
		//cout<<transaction[1]<<endl;
		
		while (1)
		{
			if(index == 3)
			{
				string hash_n =LongToString(index);
				hash_n.append(nonce);
				hash_n.append(transaction[index-1]);
				hash_n.append(previous_hash);
				//index + nonce + transaction + previous
				
    			string target_hash = sha256(hash_n);   //創建一個新的sha-256加密器 //把hashs_n丟進去
    			/*if(index==3)
					cout<<target_hash<<endl;*/
    			
    			if (target_hash[0] == '0' && target_hash[1] == '0' && target_hash[2] == '0' && target_hash[3] == '0') //target_hash[:prefixed] == '0'*prefixed:  //檢查是否符合條件
      			{
		  			previous_hash = target_hash;
		  			//cout<<previous_hash<<endl;
		  			third_nonce = nonce;
		  			nonce = "1";
      	  			index++;
      	  	
      	  			if(index>3)
      	  			{
      	  				break;
      	  			}
      			}
    			else
    			{
       				nonce = Sum(nonce, "1");       //不符合條件則nonce+1
				}
			}
			else if(index == 2)
			{
				string hash_n = LongToString(index);
				hash_n.append(second_nonce);
				hash_n.append(transaction[1]);
				hash_n.append(first_block_hash);
				
				string target_hash = sha256(hash_n);
				
				if (target_hash[0] == '0' && target_hash[1] == '0' && target_hash[2] == '0' && target_hash[3] == '0') //target_hash[:prefixed] == '0'*prefixed:  //檢查是否符合條件
      			{
		  			previous_hash = target_hash;
		  	
		  			nonce = "1";
      	  			index++;
      			}
    			else
    			{
    				previous_hash = target_hash;
       				break;       //不符合條件則nonce+1
				}
			}
		}
		
		//cout<<previous_hash<<endl;
		//cout<<key<<endl;
		if (previous_hash.compare(key) != 0)
			money_guess = Sum(money_guess, "1");
		if (previous_hash.compare(key) == 0)
			true_money = true;
	}
	
	ll total = 0;
	int and_num=0;
	for(int j=0; j < transaction[0].length() ;j++)
		if(transaction[0][j] =='&')
		{
			transaction[0][j] = ' ';
			and_num++; 
		}
	string all_transaction = transaction[0] + " " + transaction[1] + " " + transaction[2];
	split(all_transaction, ' ');
	
	for(int j=0;j<=(2+and_num)*5;j+=5)
	{
		if(_strings[j].compare("Alice") == 0)
		total -= StringToLong(_strings[j+3]);
		if(_strings[j+2].compare("Alice") == 0)
		total += StringToLong(_strings[j+3]);
	}
	
	cout<<money_guess<<","<<total<<","<<third_nonce;	
    
   	return 0;
	
	}

string Sum(string str1, string str2)
{
    // Before proceeding further, make sure length
    // of str2 is larger.
    if (str1.length() > str2.length())
        swap(str1, str2);
 
    // Take an empty string for storing result
    string str = "";
 
    // Calculate length of both string
    int n1 = str1.length(), n2 = str2.length();
 
    // Reverse both of strings
    reverse(str1.begin(), str1.end());
    reverse(str2.begin(), str2.end());
 
    int carry = 0;
    for (int i=0; i<n1; i++)
    {
        // Do school mathematics, compute sum of
        // current digits and carry
        int sum = ((str1[i]-'0')+(str2[i]-'0')+carry);
        str.push_back(sum%10 + '0');
 
        // Calculate carry for next step
        carry = sum/10;
    }
 
    // Add remaining digits of larger number
    for (int i=n1; i<n2; i++)
    {
        int sum = ((str2[i]-'0')+carry);
        str.push_back(sum%10 + '0');
        carry = sum/10;
    }
 
    // Add remaining carry
    if (carry)
        str.push_back(carry+'0');
 
    // reverse resultant string
    reverse(str.begin(), str.end());
 
    return str;
}
string LongToString(ll long_num)
{
    stack<char> stringStack;
    string signValue = "";
  
    // if long number is negative store the negative sign to
    // the signValue variable
    if (long_num < 0) {
        signValue = "-";
        long_num = -long_num;
    }
  
    // while number is greate than 0, get last digit from it
    // and convert it to character by adding '0' to it, and
    // push to the stack.
    while (long_num > 0) {
        char convertedDigit = long_num % 10 + '0';
        stringStack.push(convertedDigit);
        long_num /= 10;
    }
  
    string long_to_string = "";
  
    // while stack is not empty pop the character one by one
    // and append to the resultant string.
    while (!stringStack.empty()) {
        long_to_string += stringStack.top();
        stringStack.pop();
    }
  
    // return the resulatant string value by appending
    // singValue to it.
    return signValue + long_to_string;
}
ll StringToLong(string ss)
{
	ll long_num=0;
	
	for(int i=0;i<ss.length();i++)
		long_num = long_num*10 + ss[i] - '0';
	
	return long_num;
}
