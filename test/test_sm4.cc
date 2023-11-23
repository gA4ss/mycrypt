#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <gtest/gtest.h>
#include <mycrypt/mycrypt.h>

using namespace mycrypt;

TEST(SM4, EnCrypt)
{
}

TEST(SM4, DeCrypt)
{
}

int main(int argc, char *argv[])
{
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}