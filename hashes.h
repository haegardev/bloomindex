/*
 *   bloomindex - Index based on Bloom Filters
 *
 *   Copyright (C) 2015  Gerard Wagener
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU Affero General Public License as
 *   published by the Free Software Foundation, either version 3 of the
 *   License, or (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Affero General Public License for more details.
 *
 *    You should have received a copy of the GNU Affero General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef HASHES_H
#define HASHES_H
#include <stdint.h>
#include <stdlib.h>
uint32_t crc32(uint32_t crc, const void *buf, size_t size);
uint32_t crc32_uint32(uint32_t value);
uint32_t normalize32(uint32_t hash_value, uint32_t num_bits);
uint32_t murmur3_32(const char *key, uint32_t len, uint32_t seed);
uint32_t murmur3_32_uint32(uint32_t value);
#endif

