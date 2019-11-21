#include <iostream>

#include "hide_str.hpp"
#include <windows.h>

int main()
{
  // Demo 1
  HIDE_STR(hide_str, "Hide String1");
  uint8_t *decrypt_string = hide_str.decrypt();
  MessageBoxA(0, (LPCSTR)decrypt_string, (LPCSTR)decrypt_string, MB_OK);
  // free memory
  hide_str.str_free(decrypt_string);
  // Demo 2
  // It is simple like a magic
  MessageBoxA(0, (LPCSTR)PRINT_HIDE_STR("Hide String2"), (LPCSTR)PRINT_HIDE_STR("Hide String2"), MB_OK);
  // test for no hide strings
  MessageBoxA(0, "NO Hide String1", "NO Hide String2", MB_OK);
}
