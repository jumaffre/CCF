// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "entropy.h"

inline int ccf_randombytes(void* buf, size_t n)
{
  auto entropy = tls::create_entropy();
  entropy->random((unsigned char*)buf, n);
}