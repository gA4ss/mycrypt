#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <gtest/gtest.h>
#include <mycrypt/mycrypt.h>

using namespace mycrypt;

TEST(SM4, ECB_Data)
{
  unsigned char text[] = "Hello, SM4!";
  unsigned char key[] = "0123456789abcdef";
  unsigned char ct[256];
  unsigned char dt[256];

  int cl = sm4_ecb_encrypt(text, sizeof(text) - 1, ct, key);
  std::cout << "ciphertext size : " << cl << std::endl;
  std::cout << "ciphertext: ";
  for (int i = 0; i < cl; ++i)
  {
    printf("%02x", ct[i]);
  }
  std::cout << std::endl;

  // 解密
  int dl = sm4_ecb_decrypt(ct, cl, dt, key);
  std::cout << "plaintext size : " << dl << std::endl;
  std::cout << "plaintext: " << dt << std::endl;
}

TEST(SM4, ECB_File)
{
}

int main(int argc, char *argv[])
{
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}