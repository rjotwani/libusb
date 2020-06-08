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
#include <stdio.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "libusb/libusb.h"
#include "libusb/libusbi.h"

void print_devs(libusb_device **devs) {
	libusb_device *dev;
	int i = 0, j = 0;
	uint8_t path[8];

	while ((dev = devs[i++]) != NULL) {
		struct libusb_device_descriptor desc;
		int r = libusb_get_device_descriptor(dev, &desc);
		if (r < 0) {
			fprintf(stderr, "failed to get device descriptor");
			return;
		}

		printf("%04x:%04x (bus %d, device %d)",
			desc.idVendor, desc.idProduct,
			libusb_get_bus_number(dev), libusb_get_device_address(dev));

		r = libusb_get_port_numbers(dev, path, sizeof(path));
		if (r > 0) {
			printf(" path: %d", path[0]);
			for (j = 1; j < r; j++)
				printf(".%d", path[j]);
		}
		printf("\n");
	}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  FuzzedDataProvider stream(data, size);
  int num_devices =
    stream.remaining_bytes() / (sizeof(libusb_device) + sizeof(unsigned long));
  libusb_device *devs[num_devices];
  libusb_context *ctx = NULL;
	int r;

	r = libusb_init(NULL);
	if (r < 0)
		return r;

  int device_idx;
  for (device_idx = 0; device_idx < num_devices; i++) {
    unsigned long session_id;
    stream.ConsumeData(&session_id, 8);
    libusb_device *dev = usbi_alloc_device(ctx, session_id);
  }

  // struct libusb_device {
  // 	usbi_mutex_t lock;
  // 	int refcnt;
  //
  // 	struct libusb_context *ctx;
  // 	struct libusb_device *parent_dev;
  //
  // 	uint8_t bus_number;
  // 	uint8_t port_number;
  // 	uint8_t device_address;
  // 	enum libusb_speed speed;
  //
  // 	struct list_head list;
  // 	unsigned long session_data;
  //
  // 	struct libusb_device_descriptor device_descriptor;
  // 	int attached;
  // };

	// cnt = libusb_get_device_list(NULL, &devs);
	// if (cnt < 0){
	// 	libusb_exit(NULL);
	// 	return (int) cnt;
	// }


	print_devs(devs);
	libusb_free_device_list(devs, 1);

	libusb_exit(NULL);
	return 0;

}
