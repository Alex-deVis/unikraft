/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2019, University Politehnica of Bucharest. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <string.h>
#include <uk/random.h>
#include <uk/config.h>
#include <uk/print.h>
#include <uk/init.h>
#include <uk/arch/random.h>

/*
 * seedc is the seed length in 32-bit integers.
 * ChaCha20 requires eight 32-bit integers for the key and two 32-bit
 * integers for the nonce, hence seedc is always 10.
 * RFC7539 specifies three 32-bit integers for the nonce, but the reference
 * implementation uses only two:
 * http://cr.yp.to/streamciphers/timings/estreambench/submissions/salsa20/chacha8/ref/chacha.c
 */
#define CHACHA_SEED_LENGTH 10

ssize_t uk_swrand_fill_buffer(void *buf, size_t buflen)
{
	size_t step, chunk_size, i;
	__u32 rd;

	step = sizeof(__u32);
	chunk_size = buflen % step;

	for (i = 0; i < buflen - chunk_size; i += step)
		*(__u32 *)((char *)buf + i) = uk_swrand_randr();

	/* fill the remaining bytes of the buffer */
	if (chunk_size > 0) {
		rd = uk_swrand_randr();
		memcpy(buf + i, &rd, chunk_size);
	}

	return buflen;
}

static int _uk_swrand_init(struct uk_init_ctx *ictx __unused)
{
	unsigned int seedc = CHACHA_SEED_LENGTH;
	__u32 seedv[CHACHA_SEED_LENGTH];
	unsigned int i;
	int ret;

	uk_pr_info("Initialize random number generator...\n");

	for (i = 0; i < seedc; i++) {
		ret = ukarch_random_seed_u32(&seedv[i]);
		if (unlikely(ret)) {
			uk_pr_err("Could not generate random seed\n");
			return ret;
		}
	}

	uk_swrand_init_r(&uk_swrand_def, seedc, seedv);

	return seedc;
}

static int uk_hwrand_init(struct uk_init_ctx *ictx __unused)
{
	return ukarch_random_init();
}

uk_early_initcall(_uk_swrand_init, 0x0);
uk_early_initcall(uk_hwrand_init, 0x0);
