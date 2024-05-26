#ifndef MCAS_SESSION_H
#define MCAS_SESSION_H


#include <string>
#include <memory>
#include "TcpConnection.h"


namespace mcas {

    struct session_t {
        TcpConnection connection;


    };

/*    class Session {
    public:
        explicit Session(TcpConnection& connection, const std::weak_ptr<TcpConnection> &a);

    private:
        std::weak_ptr<TcpConnection> connection;
    };*/

}

#endif //MCAS_SESSION_H
