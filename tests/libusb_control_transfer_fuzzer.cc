// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include <fuzzer/FuzzedDataProvider.h>

#include "libusb/libusb.h"
#include "libusb/libusbi.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  struct libusb_transfer *transfer;
  FuzzedDataProvider stream(data, size);
  uint8_t bmRequestType = stream.ConsumeIntegral<uint8_t>();
  uint8_t bRequest = stream.ConsumeIntegral<uint8_t>();
  uint16_t wValue = stream.ConsumeIntegral<uint16_t>();
  uint16_t wIndex = stream.ConsumeIntegral<uint16_t>();
  uint16_t wLength = stream.ConsumeIntegral<uint16_t>();

  libusb_context *ctx = NULL;
  unsigned long session_id;
  stream.ConsumeData(&session_id, 8);

  libusb_device *dev = usbi_alloc_device(ctx, session_id);
  libusb_device_handle *dev_handle;
  libusb_open(dev, &dev_handle);

  std::vector<char> data_ = stream.ConsumeRemainingBytes<char>();

  libusb_control_transfer(dev_handle, bmRequestType, bRequest,
		wValue, wIndex, data, wLength, timeout)

  return 0;

}
