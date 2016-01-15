//
//  main.c
//  dsatest
//
//  Created by Summer on 12/20/15.
//  Copyright © 2015 summer. All rights reserved.
//

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;
#include <string>
using std::string;
#include <cstring>

#include "cryptlib.h"
using CryptoPP::Exception;

#include "files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "filters.h"
using CryptoPP::ArraySink;
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::StringStore;
using CryptoPP::Redirector;

using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;

#include "dsa.h"
using CryptoPP::DSA;

#include "assert.h"

void SaveKey( const DSA::PrivateKey& PrivateKey, const string& filename );
void LoadKey( const string& filename, DSA::PrivateKey& PrivateKey );
void SaveKey( const DSA::PublicKey& PublicKey, const string& filename );
void LoadKey( const string& filename, DSA::PublicKey& PublicKey );

AutoSeededRandomPool rng;
DSA::PrivateKey PrivateKey;
DSA::PublicKey PublicKey;

void doUsage()
{
    cout<<"Usage:"<<endl;
}

int doGenerateKey(int argc, char* argv[])
{
    
    string keyName = "id_dsa";
    for(int i=2; i<argc; ++i)
    {
        if(!strcmp(argv[i],"-o"))
        {
            if(i+1 < argc)
            {
                keyName = (argv[i+1]);
            }
            else
            {
                printf("%s\n", "No specified filename after -o");
                exit(0);
            }
        }
    }
    // Generate Private Key
    
    PrivateKey.GenerateRandomWithKeySize(rng, 1024);
    if (!PrivateKey.Validate(rng, 3))
    {
        throw("DSA key generation failed");
    }
    SaveKey( PrivateKey, keyName );
    
    PublicKey.AssignFrom(PrivateKey);
    SaveKey(PublicKey, keyName + ".pub" );
    return 0;
}

int doReadKey(int argc, char* argv[], DSA::PrivateKey &PrivateKey)
{
    string keyName = "id_dsa";
    for(int i=2; i<argc; ++i)
    {
        if(!strcmp(argv[i],"-k"))
        {
            if(i+1 < argc)
            {
                keyName = (argv[i+1]);
            }
            else
            {
                printf("%s\n", "No specified key file after -k");
                exit(0);
            }
        }
    }
    LoadKey(keyName, PrivateKey);
    return 0;
}

int doReadKey(int argc, char* argv[], DSA::PublicKey &PublicKey)
{
    string keyName = "id_dsa";
    for(int i=2; i<argc; ++i)
    {
        if(!strcmp(argv[i],"-k"))
        {
            if(i+1 < argc)
            {
                keyName = (argv[i+1]);
            }
            else
            {
                printf("%s\n", "No specified key file after -k");
                exit(0);
            }
        }
    }
    LoadKey(keyName, PublicKey);
    return 0;
}

int doSigning(int argc, char* argv[])
{
    doReadKey(argc, argv, PrivateKey);
    bool hasFileParam = false;
    string filename = "a";
    for(int i=2; i<argc; ++i)
    {
        if(!strcmp(argv[i], "-i"))
        {
            if(i+1 < argc)
            {
                filename = (argv[i+1]);
                hasFileParam = true;
            }
            else
            {
                printf("%s\n", "No specified filename after -i");
                exit(0);
            }
        }
    }
    if(!hasFileParam)
    {
        printf("%s\n", "Must specified filename after -i");
        exit(0);
    }
    DSA::Signer signer( PrivateKey );
    
    FileSource(filename.c_str(), false,
               new SignerFilter( rng, signer,
                                new FileSink((filename + ".sig").c_str(), true)
                                )//SigerFilter
               , true
               ); //FileSource
    return 0;
}

int doVerify(int argc, char* argv[])
{
    string filename = "test.pem";
    bool hasFileParam = false;
    doReadKey(argc, argv, PublicKey);
    for(int i=2; i<argc; ++i)
    {
        if(!strcmp(argv[i], "-i"))
        {
            if(i+1 < argc)
            {
                filename = (argv[i+1]);
                hasFileParam = true;
            }
            else
            {
                printf("%s\n", "No specified filename after -i");
                exit(0);
            }
        }
    }
    if(!hasFileParam)
    {
        printf("%s\n", "Must specified filename after -i");
        exit(0);
    }
    DSA::Verifier verifier( PublicKey );
    
    FileSource( filename.c_str(), false,
               new SignatureVerificationFilter(
                                               verifier, NULL,
                                               SignatureVerificationFilter::THROW_EXCEPTION
                                               )
               );
    
    cout << "Verified signature on message" << endl;
    return 0;
}

int main(int argc, char* argv[])
{
    cout<<"hello"<<endl;
    if(argc < 2)
    {
        doUsage();
        return -1;
    }
    try
    {
        if(!strcmp(argv[1], "keygen"))
        {
            return doGenerateKey(argc, argv);
        }
        else if(!strcmp(argv[1], "sign"))
        {
            return doSigning(argc, argv);
        }
        else if(!strcmp(argv[1], "verify"))
        {
            return doVerify(argc, argv);
        }
        
    }
    catch( SignatureVerificationFilter::SignatureVerificationFailed& e )
    {
        cerr << "caught SignatureVerificationFailed..." << endl;
        cerr << e.what() << endl;
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "caught Exception..." << endl;
        cerr << e.what() << endl;
    }
    
    return 0;
}

void SaveKey( const DSA::PublicKey& PublicKey, const string& filename )
{
    // DER Encode Key - X.509 key format
    PublicKey.Save(
                   FileSink( filename.c_str(), true /*binary*/ ).Ref()
                   );
}

void SaveKey( const DSA::PrivateKey& PrivateKey, const string& filename )
{
    // DER Encode Key - PKCS #8 key format
    PrivateKey.Save(
                    FileSink( filename.c_str(), true /*binary*/ ).Ref()
                    );
}

void LoadKey( const string& filename, DSA::PublicKey& PublicKey )
{
    // DER Encode Key - X.509 key format
    PublicKey.Load(
                   FileSource( filename.c_str(), true, NULL, true /*binary*/ ).Ref()
                   );
}

void LoadKey( const string& filename, DSA::PrivateKey& PrivateKey )
{
    // DER Encode Key - PKCS #8 key format
    PrivateKey.Load(
                    FileSource( filename.c_str(), true, NULL, true /*binary*/ ).Ref()
                    );
}

void VerifyMessageThrow1( const DSA::PublicKey& PublicKey,
                         const string& message, const string& signature )
{
    DSA::Verifier verifier( PublicKey );
    
    StringSource( signature+message, true,
                 new SignatureVerificationFilter(
                                                 verifier, NULL,
                                                 SignatureVerificationFilter::THROW_EXCEPTION |
                                                 SignatureVerificationFilter::SIGNATURE_AT_BEGIN
                                                 )
                 );
}

void VerifyMessageThrow2( const DSA::PublicKey& PublicKey,
                         const string& message, const string& signature )
{
    DSA::Verifier verifier( PublicKey );
    
    StringSource( message+signature, true,
                 new SignatureVerificationFilter(
                                                 verifier, NULL,
                                                 SignatureVerificationFilter::THROW_EXCEPTION
                                                 )
                 );
}

void VerifyMessageNoThrow1(const DSA::PublicKey& PublicKey,
                           const string& message, const string& signature )
{
    DSA::Verifier verifier( PublicKey );
    
    bool result = false;
    StringSource( message+signature, true,
                 new SignatureVerificationFilter(
                                                 verifier,
                                                 new ArraySink( (byte*)&result, sizeof(result ) ),
                                                 SignatureVerificationFilter::PUT_RESULT                
                                                 )
                 );
}

void VerifyMessageNoThrow2(const DSA::PublicKey& PublicKey,
                           const string& message, const string& signature )
{    
    DSA::Verifier verifier( PublicKey );
    
    SignatureVerificationFilter svf(
                                    verifier
                                    ); // SignatureVerificationFilter
    
    StringSource( signature+message, true,
                 new Redirector( svf )
                 ); // StringSource
    
    bool b = svf.GetLastResult();
}


