#include <ctime>
#include <iostream>
#include <string>
#include <boost/bind/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/ptr_container/ptr_list.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/asio.hpp>
#include <bitset>

#include "src/protocol/handshake.h"
#include "src/protocol/login.h"
#include "src/protocol/protocol.h"
#include "src/leb128.h"

#include <openssl/evp.h>
#include <openssl/aes.h>
#include "src/encryption/RSAEncryption.h"
#include "src/encryption/AESEncryption.h"

#include "src/hash.h"
#include "src/TcpConnection.h"

using boost::asio::ip::tcp;

class tcp_server {
public:
    tcp_server(boost::asio::io_context &io_context)
            : io_context_(io_context),
              acceptor_(io_context, tcp::endpoint(tcp::v4(), 1234)) {
        start_accept();
    }

    void unregister(mcas::TcpConnection::pointer connection) {
        connections.remove(connection);
    }

private:
    std::list<mcas::TcpConnection::pointer> connections;

    void start_accept() {
        mcas::TcpConnection::pointer new_connection = mcas::TcpConnection::create(io_context_);

        tcp::socket &streamSocket = new_connection->socket();
        acceptor_.async_accept(streamSocket,
                               boost::bind(&tcp_server::handle_accept, this, new_connection,
                                           boost::asio::placeholders::error));
    }

    void handle_accept(const mcas::TcpConnection::pointer new_connection,
                       const boost::system::error_code &error) {
        if (!error) {
            connections.push_back(new_connection);
            new_connection->start();
        }

        start_accept();
    }

    boost::asio::io_context &io_context_;
    tcp::acceptor acceptor_;
};


int main() {
    try {
        boost::asio::io_context io_context;
        tcp_server server(io_context);
        io_context.run();
    }
    catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}