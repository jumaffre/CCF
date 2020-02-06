// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "../secretsharing.h"

#include <doctest/doctest.h>

using namespace ccf;

TEST_CASE("Simple secret sharing example")
{
  auto ctx = SecretSharingContext();
}