#pragma once
#include <array>
#include <cstdarg>

#include "xtea3.h"
#include "murmurhash.h"
#include <random>

#define BEGIN_NAMESPACE( x ) namespace x {
#define END_NAMESPACE }

BEGIN_NAMESPACE(StringCompileTime)

int randInt() {
  std::random_device random_device; // create object for seeding
  std::mt19937 engine{ random_device() }; // create engine and seed it
  std::uniform_int_distribution<> dist(10000000, 90000000); // create distribution for integers with [1; 9] range
  return dist(engine);
}
int randkey = randInt();

constexpr auto time = __TIME__;
constexpr auto seed =
  static_cast<int>(time[7]) + static_cast<int>(time[6]) * 10
  + static_cast<int>(time[4]) * 60 + static_cast<int>(time[3]) * 600
  + static_cast<int>(time[1]) * 3600 + static_cast<int>(time[0]) * 36000;

template <int N>
struct RandomGeneratorString
{
 private:
  static constexpr unsigned a = 16807;
  static constexpr unsigned m = 2147483647;
  static constexpr unsigned s = RandomGeneratorString < N - 1 >::value;
  static constexpr unsigned lo = a * (s & 0xFFFF);
  static constexpr unsigned hi = a * (s >> 16);
  static constexpr unsigned lo2 = lo + ((hi & 0x7FFF) << 16);
  static constexpr unsigned hi2 = hi >> 16;
  static constexpr unsigned lo3 = lo2 + hi;
 public:
  static constexpr unsigned max = m;
  static constexpr unsigned value = lo3 > m ? lo3 - m : lo3;
};

template <>
struct RandomGeneratorString< 0 >
{
  static constexpr unsigned value = seed;
};

template < int N, int M >
struct RandomInt
{
  static constexpr auto value = RandomGeneratorString < N + 1 >::value % M;
};

template < int N >
struct RandomChar
{
  static const char value = static_cast<char>(1 + RandomInt < N, 0x7F - 1 >::value);
};

// Create class for hiding string
template <size_t N, int K>
class HideString : protected xtea3
{
 private:
  const char _key;
  uint32_t key_for_xtea3[8];
  uint8_t *crypted_str;
  std::array < char, N + 1 > _encrypted;
  constexpr char enc(char c) const
  {
    return c ^ _key;
  }

  char dec(char c) const
  {
    return c ^ _key;
  }
 public:
  // Constructor
  template < size_t... Is >
  constexpr __forceinline HideString(const char *str, std::index_sequence< Is... >)
    : _key(RandomChar< K >::value),

      _encrypted
  {
    enc(str[Is])...

  }
  {
    // key for xtea3
    uint32_t value_for_gen_key = randkey;
    // gen pass for XTEA3
    for (int i = 0; i < 8; i++)
    {
      key_for_xtea3[i] = Murmur3(&value_for_gen_key, sizeof(value_for_gen_key), i);
    }
    // crypt
    crypted_str = data_crypt((const uint8_t *)_encrypted.data(), key_for_xtea3, N);
  }

  // pointer for decrypted string
  __forceinline uint8_t *decrypt(void)
  {
    // key for xtea3
    uint32_t value_for_gen_key = randkey;
    // gen pass for XTEA3
    for (int i = 0; i < 8; i++)
    {
      key_for_xtea3[i] = Murmur3(&value_for_gen_key, sizeof(value_for_gen_key), i);
    }
    // decrypt
    uint8_t *decrypted_str = data_decrypt(crypted_str, key_for_xtea3, this->get_crypt_size());
    if (decrypted_str == NULL) return NULL;
    for (size_t i = 0; i < N; ++i)
    {
      decrypted_str[i] = dec(decrypted_str[i]);
    }
    decrypted_str[N] = '\0';
    return decrypted_str;
  }

  // pointer for encrypted string
  __forceinline uint8_t *crypt(void)
  {
    return crypted_str;
  }

  // free memory
  __forceinline void str_free(uint8_t *ptr)
  {
    free(ptr);
  }
};
#define HIDE_STR(hide, s) auto hide = StringCompileTime::HideString<sizeof(s) - 1, __COUNTER__ >(s, std::make_index_sequence<sizeof(s) - 1>())
#define PRINT_HIDE_STR(s) (StringCompileTime::HideString<sizeof(s) - 1, __COUNTER__ >(s, std::make_index_sequence<sizeof(s) - 1>()).decrypt())

END_NAMESPACE