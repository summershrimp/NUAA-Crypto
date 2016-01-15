#include <stdio.h>
#include <stdlib.h>

int primeTable []= {
2,3,5,7,11,13,17,19,23,29,
31,37,41,43,47,53,59,61,67,71,
73,79,83,89,97,101,103,107,109,113,
127,131,137,139,149,151,157,163,167,173,
179,181,191,193,197,199,211,223,227,229,
233,239,241,251,257,263,269,271,277,281
};
int ExtendedEuclid( int f,int d ,int *result)
{
    int x1,x2,x3,y1,y2,y3,t1,t2,t3,q;

    x1 = y2 = 1;
    x2 = y1 = 0;
    x3 = ( f>=d )?f:d;
    y3 = ( f>=d )?d:f;

    while( 1 )
    {
        if ( y3 == 0 ) 
        {
            *result = x3; /* 两个数不互素则result为两个数的最大公约数，此时返回值为零 */
            return 0;
        }
        if ( y3 == 1 ) 
        {
            *result = y2; /* 两个数互素则resutl为其乘法逆元，此时返回值为1 */
            return 1;
        }
        q = x3/y3;
        t1 = x1 - q*y1;
        t2 = x2 - q*y2;
        t3 = x3 - q*y3;
        x1 = y1;
        x2 = y2;
        x3 = y3;
        y1 = t1;
        y2 = t2;
        y3 = t3;
    }
}

int pow_mod(int m, int k, int n)
{
    int r=1, base=m;
    while(k != 0)
    {
        if(k & 1)
            r= (r * base) % n;
        base= (base * base) % n;
        k>>=1;
    }
    return r;
}

int Btest(int a, int n)
{
    int s = 0, t = n - 1;
    while (t % 2 == 0) {
        t /= 2; s++;
    }
    int x = 1;
    for (int i = 0; i < t; i++) {
        x = x * a % n;
    }
    if (x == 1 || x == n - 1) {
        return 1;
    }
    for (int i = 0; i < s; i++) {
        x = x * x % n;
        if (x == n - 1) {
            return 1;
        }
    }
    return 0;
}

int MillRab(int n)
{
    srand((unsigned)time(NULL));
    int a = rand() % (n - 3) + 2;
    return Btest(a,n);
}

int RepeatMillRab(int n, int k)
{
    for (int i = 0; i < k; i++) {
        if (!MillRab(n)) {
            return 0;
        }
    }
    return 1;
}

int encrypt(int m, int e, int n)
{
    return pow_mod(m, e, n);
}

int decrypt(int c, int d, int n)
{
    return pow_mod(c, d, n);
}
char *trans[128];
void genctrans()
{
    char a;
    for(a='A'; a<='Z'; ++a)
    {
        trans[a]= a - 'A' + 1;
    }
    trans[' '] = 0;
}
void gdectrans()
{
    int i;
    for(i=1; i<=16; i++)
    {
        trans[i]= 'A' + i - 1;
    }
    trans[0] = ' ';
}
void RSAEncrypt(char *src, int* dst, int *dlen, int e, int n)
{
    genctrans();
    int i = 0, len = strlen(src), j=0;
    int enint=0;
    int dstint;
    while( i++ < len)
    {
        if( i % 2 )
        {
            enint *= 100;
            enint += src[i];
            dstint = encrypt(enint, e, n);
            dst[j++] = dstint;
        }
        else
        {
            enint = src[i];
        }
    }
    if( len%2 )
    {
        enint *= 100;
        enint += src[i];
        dstint = encrypt(enint, e, n);
        dst[j++] = dstint;
    }
    *dlen=j;
}

void RSADecrypt(int *src, char* dst, int slen, int d, int n)
{
    gdectrans();
    int i = 0, len = slen, j=0;
    int l1,l2;
    int dstint;
    while( i++ < len)
    {
        dstint = decrypt(src[i], d, n);
        l2=dstint%100;
        l1=dstint/100;
        dst[j]=l1;
        dst[j+1]=l2;
        j+=2;
    }
    dst[j]=0;
}
int gcd(int a,int b)  
{  
    int r;  
    while(b>0)  
    {  
         r=a%b;  
         a=b;  
         b=r;  
    }  
    return a;  
}  
int genprime()
{
    return primeTable[ rand() % 50 ];
}

void GenKey(int *n, int *e, int *d)
{
    srand((unsigned)time(NULL));
    int p=genprime();
    int q=genprime();

    printf("is p prime? %d\n",RepeatMillRab(p, 10));
    
    printf("is q prime? %d\n",RepeatMillRab(q, 10));
    
    int fai=(p-1)*(q-1);
    int i;
    *n = p * q;
    for(i=2; i<fai; ++i)
    {
        if(gcd(i, fai) == 1)
        {
            (*e)=i;
            break;
        }
    }
    ExtendedEuclid(  *e, fai,  d);
    /*if (*d<0 )
         *d = (fai - *d) % fai ;
    /*///printf("%d, %d, %d, %d, %d, %d\n", p, q, fai, *n, *e, *d);
}