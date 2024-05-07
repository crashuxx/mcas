#include "TcpConnection.h"
#include "protocol/protocol.h"
#include "leb128.h"
#include <iostream>
#include <limits>

namespace mcas {

    void handshake_handler(TcpConnection &connection, std::vector<char>::iterator &begin, std::vector<char>::iterator &end);

    void empty(TcpConnection &, std::vector<char>::iterator &, std::vector<char>::iterator &) {
    }

    void dump(TcpConnection &, std::vector<char>::iterator &begin, std::vector<char>::iterator &end) {
        auto it = begin;

        std::cout << end - begin << " <- ";

        while (it != end) {
            printf("%02x ", (uint8_t) *it);
            it = next(it);
        }
        std::cout << std::endl;
    }

    TcpConnection::pointer TcpConnection::create(boost::asio::io_context &io_context) {
        return pointer(new TcpConnection(io_context));
    }

    TcpConnection::TcpConnection(boost::asio::io_context &io_context)
            : _socket(io_context), message_handler(handshake_handler) {
    }

    tcp::socket &TcpConnection::socket() {
        return _socket;
    }

    void TcpConnection::handle_write(const boost::system::error_code &error, size_t bytes_transferred) {
    }

    void TcpConnection::start() {
        std::cerr << "New connection " << _socket.remote_endpoint().address().to_string() << std::endl;
        _data.resize(1024);
        do_read();
    }

    void TcpConnection::do_read() {
        _socket.async_read_some(
                boost::asio::buffer(_data),
                [this](boost::system::error_code ec, std::size_t length) {
                    if (ec) {
                        closeAndUnregister();
                        return;
                    }

                    if (length > 0) {
                        /*do {
        _socket.read_some()
    } while (_socket.available());*/

                        if (_aesEncryption != nullptr) {
                            std::vector<char> decoded;
                            size_t ret = _aesEncryption->decrypt(decoded, _data.data(), length);
                            if (ret != length) {
                                std::cerr << "Decryption failed. Closing" << std::endl;
                                closeAndUnregister();
                                return;
                            }

                            handleMessage(length, decoded);
                        } else {
                            handleMessage(length, _data);
                        }
                    }

                    if (_socket.is_open()) do_read();
                }
        );
    }

    void TcpConnection::handleMessage(size_t length, std::vector<char> &data) {
        int32_t packetLength;
        auto begin = data.begin();
        assert(length <= std::numeric_limits<std::vector<char>::difference_type>::max());
        auto end = next(begin, length);

        do {
            auto bytes_read = pt_read_int32_t(begin, end, &packetLength);
            if (bytes_read <= 0 || packetLength + bytes_read > length) {
                std::cerr << "Malformed data. Closing" << std::endl;
                closeAndUnregister();
                return;
            }
            assert(packetLength + bytes_read <= length);

            begin = next(begin, bytes_read);
            auto packetEnd = next(begin, packetLength);
            dump(*this, begin, end);
            (*message_handler)(*this, begin, packetEnd);
            begin = packetEnd;
        } while (begin < end);
    }

    void TcpConnection::setMessageHandler(message_handler_ptr handler) {
        this->message_handler = *handler;

    }

    void TcpConnection::closeAndUnregister() {
        std::cout << "Closing" << std::endl;
        _socket.close();
        //todo
    }

    void TcpConnection::send(const std::vector<char> &data) {
        auto it = data.begin();
        auto end = data.end();
        std::cout << end - it << " -> ";

        while (it < end) {
            printf("%02x ", (uint8_t) *it);
            it = next(it);
        }
        std::cout << std::endl;

        std::vector<char> tmp;
        tmp.reserve(data.size()+8);
        leb128_encode(tmp, data.size());
        memcpy(tmp.data()+2, data.data(), data.size());
        std::copy(data.begin(), data.end(), std::back_inserter(tmp));

        if (_aesEncryption == nullptr)
            _send = tmp;
        else {
            size_t ret = _aesEncryption->encrypt(_send, (void *) tmp.data(), tmp.size());
            if (ret != tmp.size()) {
                std::cerr << "Encryption failed. Closing" << std::endl;
                closeAndUnregister();
            }
        }

        if (!_socket.is_open()) return;

        boost::asio::async_write(this->_socket, boost::asio::buffer(_send),
                                 [this](boost::system::error_code ec, std::size_t length) {
                                     this->handle_write(ec, length);
                                 });
    }

    encryption::RSAEncryption &TcpConnection::rsaEncryption() {
        if (_rsaEncryption == nullptr) {
            std::shared_ptr<encryption::RSAEncryption> tmp(new encryption::RSAEncryption());
            _rsaEncryption = tmp;
        }
        return *_rsaEncryption;
    }

    void TcpConnection::aesEncryption(std::shared_ptr<encryption::AESEncryption> &aesEncryption) {
        _aesEncryption = aesEncryption;
    }
} // mcas