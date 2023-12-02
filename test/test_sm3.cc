#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <gtest/gtest.h>
#include <mycrypt/mycrypt.h>

using namespace mycrypt;

void print_digest(unsigned char* digest)
{
  for (int i = 0; i < 32; i++)
    printf("%x", digest[i]);
  printf("\n");
}

std::string digest_to_str(unsigned char* digest, bool bigcase = false)
{
  const std::string hex = !bigcase ? "0123456789abcdef" : "0123456789ABCDEF";
  std::stringstream ss;

  for (int i = 0; i < 32; i++)
    ss << hex[(unsigned char)digest[i] >> 4] << hex[(unsigned char)digest[i] & 0xf];
  return ss.str();
}

TEST(SM3, sm3)
{
  unsigned char digest[32];
  char *data = "hello world!!!";
  sm3((unsigned char*)data, strlen(data), digest);
  // print_digest(digest);
  EXPECT_STREQ(digest_to_str(digest, true).c_str(), "190E2430DD167E136564317CF169341BC2BE0900F6830C792067CE431D7553FF");

  data = "大鲲智联";
  sm3((unsigned char*)data, strlen(data), digest);
  // print_digest(digest);
  EXPECT_STREQ(digest_to_str(digest, true).c_str(), "28281DA96BB43B9FC7ABC268DAD842AE6FB8527964EC0A248F7755542E1C5387");
}

TEST(SM3, hmac)
{
  char *key = "crackme";
  unsigned char digest[32];
  char *data = "hello world!!!";
  sm3_hmac((unsigned char*)data, strlen(data), (unsigned char*)key, strlen(key), digest);
  // print_digest(digest);
  EXPECT_STREQ(digest_to_str(digest).c_str(), "2f6061f189773cb3b168759879e3c7ec226cee7a87b649a393809af9d664fd36");

  data = "大鲲智联";
  sm3_hmac((unsigned char*)data, strlen(data), (unsigned char*)key, strlen(key), digest);
  // print_digest(digest);
  EXPECT_STREQ(digest_to_str(digest).c_str(), "15a77e05268f410d3eacc6ebcbed31b6c91ac02bd6679a974dd0230fd62e5540");
}

TEST(SM3, file)
{
  unsigned char digest[32] = {0};
  sm3_file("/home/ga4ss/workspace/mycrypt/test/nanan.jpg", digest);
  EXPECT_STREQ(digest_to_str(digest).c_str(), "e6f8159b6fdd2584f3eec3a47ad85c9a161866a285554e7ac1549d49d41f9ef6");
}

TEST(SM3, hmac_file)
{
  char *key = "crackme";
  unsigned char mac[32] = {0};
  sm3_hmac_file("/home/ga4ss/workspace/mycrypt/test/nanan.jpg", (unsigned char *)key, strlen(key), mac);
  EXPECT_STREQ(digest_to_str(mac).c_str(), "da4dbfbc689ea63a82e186dd4b38817b3e0609745bb24c4dcbac66af6c108b05");
}

int main(int argc, char *argv[])
{
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}