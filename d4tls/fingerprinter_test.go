package d4tls

import (
	"strings"
	"testing"
	"time"

	"github.com/D4-project/sensor-d4-tls-fingerprinting/etls"
	"github.com/google/gopacket"
)

var d4ClientHelloPacket = []byte{
	0x16, 0x03, 0x01, 0x00, 0x89, 0x01, 0x00, 0x00, 0x85, 0x03, 0x03, 0x49, 0xdd,
	0x95, 0x76, 0x1f, 0xd8, 0x43, 0x9c, 0xf4, 0x66, 0xd5, 0xf0, 0x8c, 0xcb, 0x37,
	0xd1, 0x55, 0xe6, 0x99, 0x1d, 0x29, 0x07, 0xe5, 0xcf, 0xdb, 0x55, 0x53, 0xc8,
	0xc3, 0xbc, 0x73, 0x27, 0x00, 0x00, 0x20, 0xc0, 0x2f, 0xc0, 0x30, 0xc0, 0x2b,
	0xc0, 0x2c, 0xcc, 0xa8, 0xcc, 0xa9, 0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x14, 0xc0,
	0x0a, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0xc0, 0x12, 0x00, 0x0a,
	0x01, 0x00, 0x00, 0x3c, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00,
	0x19, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0d, 0x00, 0x12, 0x00, 0x10,
	0x04, 0x01, 0x04, 0x03, 0x05, 0x01, 0x05, 0x03, 0x06, 0x01, 0x06, 0x03, 0x02,
	0x01, 0x02, 0x03, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00, 0x00,
}

var d4ServerHelloPacket = []byte{

	0x16, 0x03, 0x03, 0x00, 0x59, 0x02, 0x00, 0x00, 0x55, 0x03, 0x03, 0x6a, 0xf0,
	0x87, 0x47, 0xfb, 0xce, 0xc4, 0xde, 0x24, 0xcb, 0x49, 0x48, 0xdf, 0x1d, 0x71,
	0x8e, 0xb5, 0xae, 0xf1, 0x9c, 0x7f, 0x0f, 0xcb, 0x39, 0xfd, 0x51, 0xcc, 0x9b,
	0x06, 0x1f, 0x79, 0xac, 0x20, 0x79, 0x0d, 0x72, 0xf7, 0xc9, 0x40, 0x83, 0xf2,
	0x95, 0xdf, 0xcc, 0xec, 0xc5, 0xd2, 0x08, 0xbf, 0x71, 0x84, 0xfd, 0xcf, 0x79,
	0xe0, 0x5f, 0x63, 0x06, 0x15, 0x49, 0x01, 0x2b, 0x6b, 0x7e, 0xba, 0xc0, 0x30,
	0x00, 0x00, 0x0d, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0b, 0x00, 0x04, 0x03,
	0x00, 0x01, 0x02, 0x16, 0x03, 0x03, 0x05, 0x4d, 0x0b, 0x00, 0x05, 0x49, 0x00,
	0x05, 0x46, 0x00, 0x05, 0x43, 0x30, 0x82, 0x05, 0x3f, 0x30, 0x82, 0x03, 0x27,
	0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00, 0xe9, 0xd2, 0x5f, 0x88, 0x34,
	0xb2, 0x95, 0xce, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
	0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x4f, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
	0x55, 0x04, 0x06, 0x13, 0x02, 0x4c, 0x55, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
	0x55, 0x04, 0x08, 0x0c, 0x02, 0x4c, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03,
	0x55, 0x04, 0x07, 0x0c, 0x0a, 0x4c, 0x75, 0x78, 0x65, 0x6d, 0x62, 0x6f, 0x75,
	0x72, 0x67, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x05,
	0x53, 0x4d, 0x49, 0x4c, 0x45, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04,
	0x0b, 0x0c, 0x05, 0x43, 0x49, 0x52, 0x43, 0x4c, 0x30, 0x1e, 0x17, 0x0d, 0x31,
	0x39, 0x30, 0x31, 0x31, 0x38, 0x30, 0x38, 0x33, 0x37, 0x32, 0x36, 0x5a, 0x17,
	0x0d, 0x32, 0x30, 0x30, 0x36, 0x30, 0x31, 0x30, 0x38, 0x33, 0x37, 0x32, 0x36,
	0x5a, 0x30, 0x4d, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
	0x02, 0x4c, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c,
	0x0a, 0x4c, 0x75, 0x78, 0x65, 0x6d, 0x62, 0x6f, 0x75, 0x72, 0x67, 0x31, 0x15,
	0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0c, 0x53, 0x4d, 0x49, 0x4c,
	0x45, 0x2c, 0x20, 0x43, 0x49, 0x52, 0x43, 0x4c, 0x31, 0x12, 0x30, 0x10, 0x06,
	0x03, 0x55, 0x04, 0x03, 0x0c, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
	0x73, 0x74, 0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
	0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00,
	0x30, 0x82, 0x02, 0x0a, 0x02, 0x82, 0x02, 0x01, 0x00, 0xbe, 0xbc, 0x26, 0x91,
	0x5e, 0xc9, 0xa0, 0x4b, 0x62, 0x9a, 0xf4, 0x78, 0x02, 0x14, 0x45, 0xc5, 0x9a,
	0x3f, 0x87, 0x9d, 0xc6, 0x4c, 0x37, 0x5a, 0xb2, 0xcc, 0x9f, 0x95, 0x16, 0xa5,
	0xf5, 0x50, 0x68, 0xda, 0x09, 0xd3, 0x9b, 0xf0, 0xc5, 0xee, 0xe2, 0xa1, 0xff,
	0x2d, 0x1f, 0x19, 0x7e, 0xb6, 0x8f, 0x64, 0xa1, 0xee, 0x64, 0xbd, 0xcf, 0xb6,
	0x57, 0x2d, 0x3d, 0x89, 0x5e, 0x43, 0x90, 0x44, 0xfd, 0x85, 0xf7, 0x64, 0x34,
	0x37, 0x77, 0x06, 0x17, 0xda, 0x6e, 0x79, 0x23, 0xae, 0xe2, 0x20, 0xe9, 0x67,
	0xd2, 0x6c, 0x54, 0x3f, 0x3f, 0x4d, 0x4c, 0x8b, 0x2d, 0x2f, 0xc4, 0xa8, 0xaa,
	0xbc, 0x44, 0x1c, 0xe1, 0xb8, 0x83, 0x69, 0x6b, 0x71, 0xab, 0x9a, 0x8d, 0xf7,
	0x20, 0x0e, 0x15, 0x01, 0x3a, 0x97, 0x64, 0x7c, 0x6c, 0x77, 0x27, 0xd2, 0x8e,
	0x18, 0x44, 0xee, 0x2d, 0xce, 0x5d, 0x69, 0xbb, 0x3b, 0x32, 0x0e, 0x08, 0x79,
	0x63, 0x74, 0x48, 0xeb, 0xe0, 0x36, 0x3e, 0xef, 0x95, 0xda, 0x47, 0x29, 0x61,
	0xed, 0x30, 0xca, 0xcf, 0xbc, 0xd8, 0xad, 0x7b, 0x8b, 0x27, 0x19, 0x46, 0xf9,
	0xd5, 0xaa, 0x31, 0xf0, 0x9e, 0x6c, 0x4e, 0x08, 0x86, 0x27, 0x15, 0x60, 0xe0,
	0x8a, 0x01, 0x86, 0x92, 0xa8, 0xaa, 0x7d, 0x80, 0xad, 0xad, 0x2e, 0xb0, 0xbe,
	0xc3, 0xe1, 0xe4, 0x0e, 0xc0, 0x0f, 0xaf, 0xc8, 0x73, 0xed, 0x94, 0x07, 0xb4,
	0x7b, 0x5c, 0x03, 0xbd, 0x93, 0xd6, 0xd1, 0x5e, 0xb5, 0xdf, 0x6d, 0xca, 0xe9,
	0xaf, 0xa0, 0xca, 0xbe, 0xdb, 0x0b, 0x94, 0x78, 0xef, 0xd2, 0x5e, 0xbc, 0x3b,
	0x81, 0xa5, 0xa0, 0x74, 0xc3, 0xd2, 0x13, 0xc5, 0xde, 0x9f, 0x9e, 0xc7, 0x8e,
	0xba, 0x28, 0x91, 0x37, 0x49, 0x2d, 0xe7, 0x60, 0x21, 0x9b, 0x48, 0x6c, 0x59,
	0x04, 0xfc, 0xee, 0xc2, 0xe6, 0x22, 0x18, 0x5c, 0x91, 0x3e, 0xdc, 0x59, 0x5a,
	0x19, 0x74, 0x27, 0xe6, 0x17, 0xa8, 0x17, 0x6a, 0xe9, 0x2f, 0x7e, 0xde, 0xd2,
	0xc4, 0x69, 0x7e, 0x7d, 0x29, 0x7d, 0xf9, 0x15, 0xde, 0x5a, 0xcb, 0xd6, 0xc6,
	0x51, 0x0a, 0x20, 0x97, 0x80, 0x4f, 0x26, 0x96, 0xeb, 0xe8, 0x52, 0xd6, 0x41,
	0x36, 0x5a, 0x95, 0x62, 0xb9, 0x94, 0x72, 0x8c, 0x74, 0x9d, 0xb6, 0x27, 0x1c,
	0x5c, 0xbe, 0x00, 0xb8, 0x2d, 0x7b, 0x9a, 0xf0, 0x12, 0x48, 0x5c, 0xb9, 0xa6,
	0xdb, 0xc9, 0xba, 0x3f, 0xe8, 0x51, 0x40, 0x7e, 0x96, 0x71, 0x10, 0xb0, 0x70,
	0x57, 0x27, 0x32, 0x38, 0x6e, 0x5d, 0xfc, 0x6a, 0xb2, 0x57, 0x93, 0xdb, 0xfe,
	0x41, 0x76, 0x88, 0xd9, 0x5f, 0xca, 0xce, 0x38, 0xd0, 0x6b, 0x60, 0xb9, 0xfc,
	0xfa, 0x58, 0xe3, 0x75, 0x44, 0xe3, 0x1b, 0x1d, 0x5f, 0x0f, 0x8e, 0x04, 0x56,
	0x82, 0x2f, 0xd2, 0x80, 0x15, 0x07, 0x2a, 0x31, 0xbf, 0x13, 0x59, 0x85, 0x02,
	0xc2, 0x61, 0x6a, 0x8a, 0x4e, 0xde, 0xfd, 0x03, 0x9c, 0x88, 0xec, 0x34, 0x43,
	0x62, 0xe2, 0xa6, 0x3c, 0x13, 0xd7, 0x6b, 0x4e, 0xce, 0xfb, 0x7d, 0x1c, 0x3a,
	0xa5, 0xc8, 0xc3, 0x70, 0x03, 0x88, 0x68, 0x75, 0xd9, 0xec, 0x3b, 0x67, 0x55,
	0x56, 0xa4, 0x06, 0x6d, 0x4c, 0x83, 0xbd, 0x39, 0x4e, 0x4f, 0x8d, 0x19, 0xb3,
	0x3f, 0x22, 0x0e, 0xfb, 0x58, 0xb5, 0xc0, 0x67, 0xdc, 0xac, 0xaa, 0x02, 0x7d,
	0x56, 0x9b, 0xb6, 0xac, 0x7f, 0x31, 0xe0, 0x18, 0x49, 0x83, 0x8f, 0x57, 0x22,
	0x27, 0x0b, 0xfc, 0x6f, 0x4f, 0xf3, 0x14, 0x08, 0xe5, 0xb5, 0x5c, 0xa7, 0x11,
	0x44, 0x82, 0x8e, 0xe8, 0xf2, 0x98, 0xcb, 0x2b, 0xe5, 0xbf, 0x44, 0x97, 0xee,
	0xf5, 0x87, 0x16, 0xd1, 0x48, 0x77, 0x78, 0x49, 0x44, 0x66, 0xa4, 0x1d, 0x87,
	0xe5, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x20, 0x30, 0x1e, 0x30, 0x0b, 0x06,
	0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x04, 0xf0, 0x30, 0x0f, 0x06,
	0x03, 0x55, 0x1d, 0x11, 0x04, 0x08, 0x30, 0x06, 0x87, 0x04, 0x7f, 0x00, 0x00,
	0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
	0x0b, 0x05, 0x00, 0x03, 0x82, 0x02, 0x01, 0x00, 0x23, 0x10, 0x2b, 0xfe, 0xda,
	0x64, 0x5c, 0x81, 0xbb, 0xb7, 0x42, 0xb4, 0x88, 0xb4, 0xae, 0x20, 0x52, 0x3d,
	0x0d, 0xe8, 0x13, 0xab, 0xb0, 0xb1, 0x4c, 0xb8, 0xbe, 0x01, 0x1d, 0x91, 0xb4,
	0x85, 0x5f, 0x3f, 0x99, 0xa5, 0x24, 0x50, 0x0d, 0x00, 0x62, 0x33, 0xe1, 0x62,
	0x71, 0xde, 0x71, 0x97, 0x9b, 0xa3, 0xcb, 0xe5, 0xdd, 0x3c, 0xb9, 0xd7, 0xfd,
	0x2c, 0xd4, 0x91, 0xa3, 0x13, 0xa4, 0xdd, 0x4d, 0x35, 0x01, 0x4d, 0x16, 0xbc,
	0xce, 0x45, 0xa7, 0x28, 0xa1, 0x7b, 0x7b, 0x63, 0x01, 0xbb, 0x4c, 0xca, 0x52,
	0xbf, 0x07, 0x64, 0x2e, 0xf7, 0xf0, 0xe2, 0xe5, 0xe8, 0x51, 0x70, 0x2b, 0x4e,
	0xdc, 0xab, 0xbc, 0x56, 0xd3, 0xfd, 0x46, 0x7e, 0xb5, 0x27, 0x37, 0xb4, 0x92,
	0x6e, 0xef, 0x2e, 0x50, 0x01, 0xfc, 0x87, 0xff, 0xec, 0xd6, 0x86, 0x03, 0x01,
	0xcf, 0x8a, 0x3b, 0xaf, 0xd6, 0x8b, 0xb3, 0x7e, 0x46, 0xdf, 0x52, 0xaf, 0x19,
	0xbd, 0xbe, 0x73, 0x25, 0x76, 0x5b, 0xf5, 0xe3, 0x02, 0xe4, 0x57, 0xd0, 0x0b,
	0xd1, 0xb6, 0xfe, 0x04, 0x36, 0xbe, 0x31, 0x8b, 0x53, 0xdd, 0x6a, 0x1b, 0xbd,
	0x99, 0xc2, 0x62, 0x8d, 0x74, 0xc8, 0x49, 0x11, 0xd8, 0x70, 0xbb, 0x92, 0xe9,
	0x42, 0x5b, 0x2c, 0x6d, 0xb1, 0x63, 0xf9, 0xfe, 0xd7, 0xe2, 0x76, 0xf3, 0x30,
	0x17, 0x0d, 0xc9, 0x86, 0x9a, 0x43, 0x86, 0x52, 0x85, 0x4c, 0x2f, 0xde, 0x1d,
	0xb7, 0x9c, 0x8e, 0x10, 0xf2, 0xea, 0xca, 0xe7, 0x98, 0xf1, 0xe0, 0xc4, 0x93,
	0x27, 0x55, 0xaf, 0xe5, 0x32, 0x63, 0xfe, 0xb2, 0x51, 0x78, 0xaf, 0xc8, 0x78,
	0xd9, 0xe4, 0xad, 0xf8, 0x1f, 0xac, 0xd6, 0x60, 0x82, 0xe8, 0x3e, 0x5c, 0x2d,
	0x96, 0x0e, 0x70, 0xf9, 0xb6, 0x0b, 0x3f, 0x7c, 0xac, 0x9c, 0x2a, 0x26, 0xbd,
	0xb4, 0xc3, 0xba, 0x6c, 0xb2, 0x06, 0xc8, 0x0b, 0xfc, 0xb5, 0x66, 0xa4, 0xaf,
	0x91, 0xfb, 0x50, 0x7a, 0x05, 0xe9, 0x23, 0xf3, 0xe4, 0xc9, 0x11, 0xd2, 0xb4,
	0xdb, 0x19, 0x39, 0xbb, 0xcb, 0xd2, 0xc9, 0x5b, 0x11, 0x26, 0x9a, 0x49, 0x04,
	0x3c, 0x64, 0xe3, 0x1a, 0xb6, 0x7f, 0x12, 0xf0, 0xb3, 0x3a, 0x89, 0x5e, 0x13,
	0x48, 0x5d, 0x05, 0x6f, 0x3c, 0x15, 0x3a, 0xa3, 0x54, 0xf8, 0x02, 0x52, 0x3e,
	0x4c, 0x87, 0x40, 0xb8, 0x7f, 0x4e, 0xce, 0x35, 0x1b, 0xe3, 0xf4, 0x5c, 0x07,
	0x65, 0xcd, 0x03, 0x70, 0x92, 0xbd, 0xee, 0xb0, 0x14, 0x91, 0x40, 0x4d, 0x44,
	0x2a, 0xfd, 0x02, 0xb9, 0x19, 0x39, 0xf5, 0x3d, 0x11, 0xee, 0xa0, 0x7e, 0xbc,
	0xbd, 0xa1, 0xff, 0x92, 0x56, 0x30, 0x36, 0x15, 0xa1, 0x6c, 0x6b, 0x13, 0x2e,
	0x5e, 0xc0, 0xbe, 0x5a, 0x26, 0xad, 0x4a, 0x78, 0xbd, 0x66, 0x14, 0xc7, 0x81,
	0x89, 0x7d, 0x7a, 0x8b, 0xea, 0xb8, 0x44, 0x30, 0x1f, 0x23, 0x0b, 0x29, 0xb9,
	0x39, 0x84, 0x82, 0x66, 0x1f, 0x2b, 0x93, 0x32, 0x08, 0x9b, 0x12, 0x08, 0xae,
	0x73, 0x59, 0x7b, 0x36, 0x06, 0x47, 0xda, 0xfd, 0xe5, 0x3a, 0x09, 0xf1, 0xb8,
	0x16, 0xb1, 0x3d, 0x2c, 0xe6, 0x4b, 0x5c, 0xe5, 0x90, 0x75, 0xba, 0x6e, 0x3f,
	0x24, 0x6b, 0xdc, 0x9a, 0xc9, 0x40, 0x84, 0xec, 0xf5, 0x53, 0x9b, 0x24, 0x8a,
	0xd4, 0x94, 0x4f, 0xda, 0x2d, 0x1a, 0xfe, 0x45, 0xa9, 0xa9, 0xf9, 0xf0, 0x35,
	0xab, 0x5d, 0xf8, 0xe1, 0xae, 0x8d, 0x7d, 0x34, 0xf9, 0x32, 0x20, 0x06, 0xdf,
	0x5e, 0x4d, 0x55, 0x53, 0x97, 0xa6, 0x97, 0xec, 0x5e, 0x65, 0x32, 0x94, 0x56,
	0x68, 0x3a, 0xd8, 0x3c, 0xb3, 0xe7, 0xd8, 0x61, 0x81, 0x19, 0x83, 0xe6, 0x43,
	0x69, 0xbb, 0x60, 0x3b, 0x7f, 0x5e, 0xa7, 0xb2, 0x8b, 0xce, 0x92, 0xfe, 0x36,
	0x16, 0x03, 0x03, 0x02, 0x2c, 0x0c, 0x00, 0x02, 0x28, 0x03, 0x00, 0x1d, 0x20,
	0x28, 0x38, 0xe3, 0xcc, 0xe4, 0x88, 0xd7, 0xb1, 0x72, 0x8b, 0x6a, 0x99, 0x7c,
	0x7a, 0xce, 0x82, 0xd5, 0x6e, 0x31, 0x81, 0x99, 0xa1, 0x5d, 0xf1, 0x9a, 0x2f,
	0x7c, 0x05, 0x88, 0x1d, 0x64, 0x28, 0x06, 0x01, 0x02, 0x00, 0x2b, 0x04, 0xb0,
	0x1b, 0x0a, 0xed, 0xe6, 0x3b, 0x73, 0x8a, 0x33, 0x00, 0x74, 0x76, 0xf6, 0x14,
	0xc6, 0x74, 0xa7, 0x93, 0x50, 0x9a, 0x97, 0x2c, 0x3f, 0x98, 0x10, 0xa0, 0x27,
	0xb8, 0xff, 0x02, 0x6c, 0x03, 0xf0, 0x9e, 0xad, 0x7f, 0x56, 0x4c, 0xa7, 0xbf,
	0xca, 0xb1, 0x07, 0xb8, 0x6a, 0x1f, 0x87, 0xe4, 0x3d, 0x5f, 0x62, 0xa9, 0x60,
	0xe1, 0x46, 0x47, 0xa4, 0xed, 0x65, 0x9d, 0xf2, 0x65, 0xd4, 0x88, 0x66, 0x13,
	0x7d, 0x91, 0x9d, 0xcf, 0xaf, 0x48, 0x08, 0x9a, 0x92, 0xa0, 0xe4, 0x9e, 0xe3,
	0x02, 0x8f, 0xa3, 0x98, 0x03, 0xc3, 0xe1, 0x25, 0x88, 0xe1, 0x7b, 0xef, 0x21,
	0x85, 0x03, 0xea, 0xf7, 0xa6, 0x15, 0x64, 0xa3, 0xde, 0x8a, 0xe3, 0x3e, 0xc1,
	0x31, 0x1b, 0xc6, 0xe6, 0x07, 0xc8, 0xd7, 0x02, 0xf9, 0x2d, 0x26, 0xf0, 0x1b,
	0xc3, 0x0b, 0xb5, 0xd2, 0x4b, 0xa7, 0xed, 0xc1, 0x1b, 0x21, 0xda, 0x77, 0x13,
	0xeb, 0x26, 0x53, 0xfa, 0x0f, 0x0e, 0xc9, 0x4d, 0x24, 0xd4, 0x23, 0xa8, 0xb8,
	0x68, 0x4c, 0xf9, 0xa3, 0x9c, 0x39, 0x16, 0xda, 0x00, 0xec, 0x62, 0x78, 0x1d,
	0x4c, 0x2c, 0x27, 0x3b, 0x81, 0xe7, 0x21, 0x72, 0x7b, 0x4f, 0x27, 0xaf, 0x9b,
	0xd0, 0x71, 0x7c, 0x17, 0xc9, 0xda, 0x8b, 0xce, 0xfe, 0x7e, 0xeb, 0xe5, 0xbc,
	0x55, 0x7b, 0xbb, 0x75, 0x51, 0xcf, 0x34, 0xf2, 0x26, 0xe6, 0x1f, 0x5c, 0x19,
	0x77, 0xf3, 0xec, 0x85, 0xf5, 0x9f, 0xac, 0xcd, 0x01, 0xc7, 0x61, 0x38, 0xb0,
	0x7f, 0x3b, 0x7d, 0x42, 0x3c, 0xb7, 0x17, 0x29, 0xeb, 0x34, 0xe9, 0x47, 0xad,
	0xcd, 0x37, 0x9f, 0xe1, 0xb3, 0xe7, 0xd3, 0xc6, 0xb7, 0xb2, 0xa7, 0x00, 0x65,
	0xda, 0xeb, 0x44, 0x0e, 0xfb, 0x5a, 0xf8, 0xfd, 0x96, 0xe0, 0x4b, 0xe3, 0x05,
	0xb6, 0xb6, 0xc6, 0xaa, 0x9d, 0x00, 0xcb, 0xe5, 0xfc, 0xa9, 0x1f, 0x44, 0x8e,
	0xfc, 0x6b, 0xef, 0xd1, 0x6d, 0x6f, 0xad, 0x0d, 0x43, 0x5a, 0x5e, 0x05, 0x10,
	0xc5, 0xdb, 0xb0, 0x57, 0xfd, 0xe3, 0xe1, 0x9f, 0x5f, 0x6e, 0x74, 0x4c, 0x4f,
	0xa3, 0x6a, 0x95, 0xc2, 0xea, 0x45, 0x98, 0x33, 0xc0, 0xa3, 0x52, 0x34, 0x37,
	0x43, 0x2f, 0x9a, 0x5c, 0x02, 0x1e, 0xa4, 0x07, 0x5e, 0x10, 0x85, 0x22, 0x03,
	0xb4, 0xf4, 0x6e, 0x22, 0x73, 0x1d, 0xf4, 0xc7, 0xe2, 0xc1, 0xd7, 0x16, 0x56,
	0x4d, 0xa1, 0xe8, 0x11, 0x8f, 0x98, 0x98, 0xef, 0x69, 0x2c, 0x19, 0x2b, 0xd1,
	0xff, 0x0d, 0x26, 0x12, 0xa7, 0x2e, 0x61, 0xe1, 0x55, 0x65, 0xba, 0x06, 0x11,
	0x86, 0x4e, 0xec, 0xa9, 0xb3, 0x3b, 0xf2, 0x22, 0x38, 0x52, 0x29, 0x1b, 0xf0,
	0x76, 0x8f, 0x6f, 0x8f, 0x58, 0xf2, 0xee, 0xa1, 0xed, 0x2c, 0xbb, 0x43, 0x42,
	0xaa, 0x96, 0xdc, 0x75, 0x8c, 0x4e, 0x0b, 0xea, 0xf0, 0xa0, 0x2a, 0x5f, 0x37,
	0x54, 0xbb, 0x65, 0xf7, 0x3a, 0xd5, 0xe8, 0x58, 0x1c, 0xb9, 0x00, 0x05, 0x02,
	0xee, 0x17, 0x11, 0x52, 0x62, 0xc6, 0xd2, 0x30, 0xbd, 0x32, 0x51, 0xd1, 0xf7,
	0xf2, 0x81, 0x86, 0x71, 0xd7, 0x16, 0x4e, 0xf4, 0x8a, 0xc7, 0x0b, 0x3a, 0xd9,
	0x55, 0x0d, 0x80, 0x1f, 0x64, 0x3e, 0x9d, 0xa3, 0x8c, 0x2a, 0x5c, 0xe0, 0x53,
	0x97, 0xef, 0x55, 0xb8, 0x78, 0x1f, 0xf8, 0x77, 0xc1, 0x34, 0xc1, 0x59, 0x2a,
	0xd3, 0xa6, 0xb7, 0x28, 0x31, 0xbe, 0x78, 0xef, 0xd5, 0x3f, 0x83, 0xbc, 0xfc,
	0xea, 0x3f, 0x72, 0xdf, 0xa6, 0x91, 0x1a, 0x05, 0x39, 0x86, 0x9d, 0x09, 0x8a,
	0x5c, 0x3d, 0x89, 0x17, 0x80, 0xb3, 0xba, 0xf5, 0x9c, 0x5f, 0x7d, 0xaf, 0x53,
	0x23, 0xe3, 0x79, 0x08, 0x24, 0x7c, 0x07, 0xaf, 0x4b, 0xd2, 0x2c, 0x19, 0xdd,
	0xc5, 0x66, 0x16, 0x03, 0x03, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00,
}

var serverHello = d4ServerHelloPacket[:94]
var certificateRecord = d4ServerHelloPacket[94:1456]

// Rest of the packet is:
// Server Key Exchange[1456:2017]
// Server Hello Done[2017:]

func TestJA3(t *testing.T) {
	var tls = &etls.ETLS{}
	var tlss = &TLSSession{}
	var decoded []gopacket.LayerType
	p := gopacket.NewDecodingLayerParser(etls.LayerTypeETLS, tls)
	err := p.DecodeLayers(d4ClientHelloPacket, &decoded)
	if err != nil {
		t.Fail()
	} else if decoded[0] == etls.LayerTypeETLS {
		if tls.Handshake != nil {
			for _, etlsrecord := range tls.Handshake {
				if etlsrecord.ETLSHandshakeMsgType == 1 {
					// Populate Client Hello related fields
					tlss.PopulateClientHello(etlsrecord.ETLSHandshakeClientHello)
					tlss.SetTimestamp(time.Now())
					tlss.D4Fingerprinting("ja3")
					t.Logf("%v", tlss.Record.JA3)
					t.Logf("%v", tlss.Record.JA3Digest)
				}
			}
		}
	}
}

func TestJA3s(t *testing.T) {
	var tls = &etls.ETLS{}
	var tlss = &TLSSession{}
	var decoded []gopacket.LayerType
	p := gopacket.NewDecodingLayerParser(etls.LayerTypeETLS, tls)
	err := p.DecodeLayers(serverHello, &decoded)
	if err != nil {
		t.Fail()
	} else if decoded[0] == etls.LayerTypeETLS {
		if tls.Handshake != nil {
			for _, etlsrecord := range tls.Handshake {
				if etlsrecord.ETLSHandshakeMsgType == 2 {
					// Populate Server Hello related fields
					tlss.PopulateServerHello(etlsrecord.ETLSHandshakeServerHello)
					tlss.D4Fingerprinting("ja3s")
					t.Logf("%v", tlss.Record.JA3S)
					t.Logf("%v", tlss.Record.JA3SDigest)
				}
			}
		}
	}
}

func TestTLSH(t *testing.T) {
	var tls = &etls.ETLS{}
	var tlss = &TLSSession{}
	var decoded []gopacket.LayerType
	p := gopacket.NewDecodingLayerParser(etls.LayerTypeETLS, tls)
	err := p.DecodeLayers(certificateRecord, &decoded)
	if err != nil {
		t.Fail()
	} else if decoded[0] == etls.LayerTypeETLS {
		if tls.Handshake != nil {
			for _, etlsrecord := range tls.Handshake {
				if etlsrecord.ETLSHandshakeMsgType == 11 {
					// Populate Cert
					tlss.PopulateCertificate(etlsrecord.ETLSHandshakeCertificate)
					tlss.D4Fingerprinting("tlsh")
					// TODO check that against the reference implementation
					t.Logf("%v", tlss.Record.TLSH)
				}
			}
		}
	}
}

func TestGreaseClientHelloExtensionExlusion(t *testing.T) {
	var tls = &etls.ETLS{}
	var tlss = &TLSSession{}
	var decoded []gopacket.LayerType
	p := gopacket.NewDecodingLayerParser(etls.LayerTypeETLS, tls)
	// Add grease values on an extension
	d4ClientHelloPacket[82] = 0x0a
	d4ClientHelloPacket[83] = 0x0a
	// Set because tests may be ran in any order
	d4ClientHelloPacket[46] = 0xc0
	d4ClientHelloPacket[47] = 0x2f
	err := p.DecodeLayers(d4ClientHelloPacket, &decoded)

	if err != nil {
		t.Fail()
	} else if decoded[0] == etls.LayerTypeETLS {
		if tls.Handshake != nil {
			for _, etlsrecord := range tls.Handshake {
				if etlsrecord.ETLSHandshakeMsgType == 1 {
					// Populate Client Hello related fields
					tlss.PopulateClientHello(etlsrecord.ETLSHandshakeClientHello)
					tlss.SetTimestamp(time.Now())
					tlss.D4Fingerprinting("ja3")
					t.Logf("%v", tlss.Record.JA3Digest)
					if strings.Index(tlss.Record.JA3, "2570") != -1 {
						t.Logf("GREASE values should not end up in JA3\n")
						t.Fail()
					}
				}
			}
		}
	}
}

func TestGreaseClientHelloCipherExlusion(t *testing.T) {
	var tls = &etls.ETLS{}
	var tlss = &TLSSession{}
	var decoded []gopacket.LayerType
	p := gopacket.NewDecodingLayerParser(etls.LayerTypeETLS, tls)
	// Add grease on a cipher suite
	d4ClientHelloPacket[46] = 0x0a
	d4ClientHelloPacket[47] = 0x0a
	// Set because tests may be ran in any order
	d4ClientHelloPacket[82] = 0x00
	d4ClientHelloPacket[83] = 0x05
	err := p.DecodeLayers(d4ClientHelloPacket, &decoded)

	if err != nil {
		t.Fail()
	} else if decoded[0] == etls.LayerTypeETLS {
		if tls.Handshake != nil {
			for _, etlsrecord := range tls.Handshake {
				if etlsrecord.ETLSHandshakeMsgType == 1 {
					// Populate Client Hello related fields
					tlss.PopulateClientHello(etlsrecord.ETLSHandshakeClientHello)
					tlss.SetTimestamp(time.Now())
					tlss.D4Fingerprinting("ja3")
					if strings.Index(tlss.Record.JA3, "2570") != -1 {
						t.Logf("GREASE values should not end up in JA3\n")
						t.Fail()
					}
				}
			}
		}
	}
}
func TestGreaseServerHelloExtensionExlusion(t *testing.T) {
	var tls = &etls.ETLS{}
	var tlss = &TLSSession{}
	var decoded []gopacket.LayerType
	p := gopacket.NewDecodingLayerParser(etls.LayerTypeETLS, tls)
	// Add grease values on an extension
	d4ServerHelloPacket[81] = 0x0a
	d4ServerHelloPacket[82] = 0x0a
	// Set because tests may be ran in any order
	d4ServerHelloPacket[76] = 0xc0
	d4ServerHelloPacket[77] = 0x30
	err := p.DecodeLayers(d4ServerHelloPacket, &decoded)
	if err != nil {
		t.Fail()
	} else if decoded[0] == etls.LayerTypeETLS {
		if tls.Handshake != nil {
			for _, etlsrecord := range tls.Handshake {
				if etlsrecord.ETLSHandshakeMsgType == 2 {
					// Populate Client Hello related fields
					tlss.PopulateServerHello(etlsrecord.ETLSHandshakeServerHello)
					tlss.D4Fingerprinting("ja3s")
					t.Logf("%v", tlss.Record.JA3S)
					if strings.Index(tlss.Record.JA3S, "2570") != -1 {
						t.Logf("GREASE values should not end up in JA3s\n")
						t.Fail()
					}
				}
			}
		}
	}
}

func TestGreaseServerHelloCipherExlusion(t *testing.T) {
	var tls = &etls.ETLS{}
	var tlss = &TLSSession{}
	var decoded []gopacket.LayerType
	p := gopacket.NewDecodingLayerParser(etls.LayerTypeETLS, tls)
	// Add grease values on an extension
	d4ServerHelloPacket[81] = 0xff
	d4ServerHelloPacket[82] = 0x01
	// Set because tests may be ran in any order
	d4ServerHelloPacket[76] = 0x0a
	d4ServerHelloPacket[77] = 0x0a
	err := p.DecodeLayers(d4ServerHelloPacket, &decoded)
	if err != nil {
		t.Fail()
	} else if decoded[0] == etls.LayerTypeETLS {
		if tls.Handshake != nil {
			for _, etlsrecord := range tls.Handshake {
				if etlsrecord.ETLSHandshakeMsgType == 2 {
					// Populate Client Hello related fields
					tlss.PopulateServerHello(etlsrecord.ETLSHandshakeServerHello)
					tlss.D4Fingerprinting("ja3s")
					t.Logf("%v", tlss.Record.JA3S)
					if strings.Index(tlss.Record.JA3S, "2570") != -1 {
						t.Logf("GREASE values should not end up in JA3s\n")
						t.Fail()
					}
				}
			}
		}
	}
}
