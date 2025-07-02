#include "mtlsp.h"

/**
 * @brief mtlsp传送
 *
 * @param client 客户端，相当于套接字
 * @param data 要传送的数据
 * @param data_len 要传送的数据长度
 * @return int 传送成功的字节数，失败为 -1
 */
int mtlsp::send(Client &client, uint8_t *data, const uint32_t data_len) {
  uint8_t prefix[4];
  uint32_t be_len = htonl(data_len);
  memcpy(prefix, &be_len, 4);
  client.write(prefix, 4);
  return client.write(data, data_len);
}

/**
 * @brief mtlsp接收
 *
 * @param client 客户端，相当于套接字
 * @param buf 传出参数，指向内存块的指针
 * @param buf_len 内存块的大小
 * @return int 接收的字节数，失败为 -1
 */
int mtlsp::recv(Client &client, uint8_t *buf, const uint32_t buf_len) {
  uint8_t prefix[4];
  // 读取长度前缀
  if (client.readBytes(prefix, 4) != 4)
    return -1;

  uint32_t len = ntohl(*reinterpret_cast<uint32_t *>(prefix));
  if (buf_len < len)
    return -1;

  // 循环读取直到满len字节
  uint32_t total_read = 0;
  while (total_read < len) {
    int bytes_read = client.read(buf + total_read, len - total_read);
    if (bytes_read <= 0)
      return -1;
    total_read += bytes_read;
  }
  return total_read;
}