#ifndef MCAS_TCPCONNECTION_H
#define MCAS_TCPCONNECTION_H

#include <boost/enable_shared_from_this.hpp>
#include <boost/asio.hpp>
#include "encryption/RSAEncryption.h"
#include "encryption/AESEncryption.h"

using boost::asio::ip::tcp;

namespace mcas {
    class TcpConnection;

    typedef void (*message_handler_ptr)(TcpConnection &, std::vector<char>::iterator &, std::vector<char>::iterator &);

    class TcpConnection : public boost::enable_shared_from_this<TcpConnection> {
    public:

        typedef boost::shared_ptr<TcpConnection> pointer;

        static pointer create(boost::asio::io_context &io_context);

        tcp::socket &socket();

        void start();

        void setMessageHandler(message_handler_ptr message_handler);

        void closeAndUnregister();

        void send(const std::vector<char> &vector);

        void aesEncryption(std::shared_ptr<encryption::AESEncryption>&);
        encryption::RSAEncryption &rsaEncryption();

    private:

        explicit TcpConnection(boost::asio::io_context &io_context);

        void do_read();

        void handle_write(const boost::system::error_code &error,
                          size_t bytes_transferred);

        tcp::socket _socket;

        std::vector<char> _data;
        std::vector<char> _send;

        message_handler_ptr message_handler;

        std::shared_ptr<encryption::AESEncryption> _aesEncryption;
        std::shared_ptr<encryption::RSAEncryption> _rsaEncryption;

        void handleMessage(size_t, std::vector<char>&);
    };

} // mcas

#endif //MCAS_TCPCONNECTION_H
