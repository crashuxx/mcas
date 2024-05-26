#include <cassert>
#include <cstring>
#include "login.h"
#include "protocol.h"
#include "../leb128.h"

namespace mcas::protocol {

    ptrdiff_t deserialize_property(std::vector<char>::iterator &begin, const std::vector<char>::iterator &end, property_t &data) {
        ptrdiff_t bytesRead;

        bytesRead = pt_read_string(begin, end, data.name);
        if (bytesRead < 0) return -1;
        begin += bytesRead;

        bytesRead = pt_read_string(begin, end, data.value);
        if (bytesRead < 0) return -1;
        begin += bytesRead;

        bool is_signed;
        pt_read_bool(begin, end, is_signed);

        if (is_signed && begin != end) {
            bytesRead = pt_read_string(begin, end, data.signature);
            if (bytesRead < 0) return -1;
            begin += bytesRead;
        }

        return std::distance(begin, end);
    }

    ptrdiff_t deserialize_properties(std::vector<char>::iterator &begin, const std::vector<char>::iterator &end, std::vector<property_t> &data) {
        ptrdiff_t bytesRead;

        int32_t properties_count;
        pt_read_varint(begin, end, properties_count);
        data.reserve(properties_count < 24 ? properties_count : 24);

        for(int i = 0; i < properties_count && begin != end; i++) {
            bytesRead = deserialize_property(begin, end, data.at(i));
            if (bytesRead < 0) return -1;
            begin += bytesRead;
        }

        return std::distance(begin, end);
    }

    ptrdiff_t serialize_property(const property_t &data, std::vector<char> &buffer) {
        ptrdiff_t size = 0, bytesWritten;

        bytesWritten = pt_write_string(buffer, data.name);
        if (bytesWritten < 0) return -1;
        size += bytesWritten;

        bytesWritten = pt_write_string(buffer, data.value);
        if (bytesWritten < 0) return -1;
        size += bytesWritten;

        // Optional field
        if (!data.signature.empty()) {
            bytesWritten = pt_write_string(buffer, data.signature);
            if (bytesWritten < 0) return -1;
            size += bytesWritten;
        }

        return size;
    }

    ptrdiff_t serialize_properties(const std::vector<property_t> &data, std::vector<char> &buffer) {
        ptrdiff_t size = 0, bytesWritten;

        bytesWritten = pt_write_varint(buffer, data.size());
        if (bytesWritten < 0) return -1;
        size += bytesWritten;

        for (const auto &item: data) {
            bytesWritten = serialize_property(item, buffer);
            if (bytesWritten < 0) return -1;
            size += bytesWritten;
        }

        return bytesWritten;
    }

    ptrdiff_t serialize_ptc_login_disconnect(const ptc_login_disconnect &data, std::vector<char> &buffer) {
        ptrdiff_t size = 0, bytesWritten;

        bytesWritten = pt_write_varint(buffer, 0x00);
        if (bytesWritten < 0) return -1;
        size += bytesWritten;

        bytesWritten = pt_write_string(buffer, data.reason);
        if (bytesWritten < 0) return -1;
        size += bytesWritten;

        return size;
    }

    ptrdiff_t deserialize_ptc_login_disconnect(std::vector<char>::iterator &begin,
                                               const std::vector<char>::iterator &end,
                                               ptc_login_disconnect &data) {
        ptrdiff_t bytesRead;

        bytesRead = pt_read_string(begin, end, data.reason);
        if (bytesRead < 0) return -1;
        begin += bytesRead;

        return std::distance(begin, end);
    }

    ptrdiff_t serialize_ptc_login_encryption_begin(const ptc_login_encryption_begin &data, std::vector<char> &buffer) {
        ptrdiff_t size = 0, bytesWritten;

        bytesWritten = pt_write_varint(buffer, 0x01);
        if (bytesWritten < 0) return -1;
        size += bytesWritten;

        bytesWritten = pt_write_string(buffer, data.serverId);
        if (bytesWritten < 0) return -1;
        size += bytesWritten;

        bytesWritten = pt_write_bytes(buffer, data.publicKey);
        if (bytesWritten < 0) return -1;
        size += bytesWritten;

        bytesWritten = pt_write_bytes(buffer, data.verifyToken);
        if (bytesWritten < 0) return -1;
        size += bytesWritten;

        return size;
    }

    ptrdiff_t serialize_ptc_login_compress(const ptc_login_compress &data, std::vector<char> &buffer) {
        ptrdiff_t size = 0, bytesWritten;

        bytesWritten = pt_write_varint(buffer, 0x03);
        if (bytesWritten < 0) return -1;
        size = bytesWritten;

        bytesWritten += pt_write_varint(buffer, data.threshold);
        if (bytesWritten < 0) return -1;
        size += bytesWritten;

        return size;
    }

    ptrdiff_t deserialize_ptc_login_compress(std::vector<char>::iterator &begin,
                                             const std::vector<char>::iterator &end,
                                             ptc_login_compress &data) {
        ptrdiff_t bytesRead;

        bytesRead = pt_read_varint(begin, end, data.threshold);
        if (bytesRead < 0) return -1;

        return bytesRead;
    }

    ptrdiff_t serialize_ptc_login_plugin_request(const ptc_login_login_plugin_request &data, std::vector<char> &buffer) {
        ptrdiff_t size = 0, bytesWritten;

        bytesWritten = pt_write_varint(buffer, 0x04);
        if (bytesWritten < 0) return -1;
        size += bytesWritten;

        bytesWritten = pt_write_varint(buffer, data.messageId);
        if (bytesWritten < 0) return -1;
        size += bytesWritten;

        bytesWritten = pt_write_string(buffer, data.channel);
        if (bytesWritten < 0) return -1;
        size += bytesWritten;

        bytesWritten = pt_write_bytes(buffer, data.data);
        if (bytesWritten < 0) return -1;
        size += bytesWritten;

        return size;
    }

    ptrdiff_t deserialize_ptc_login_plugin_request(std::vector<char>::iterator &begin,
                                                   const std::vector<char>::iterator &end,
                                                   ptc_login_login_plugin_request &data) {
        ptrdiff_t bytesRead;

        bytesRead = pt_read_varint(begin, end, data.messageId);
        if (bytesRead < 0) return -1;
        begin += bytesRead;

        bytesRead = pt_read_string(begin, end, data.channel);
        if (bytesRead < 0) return -1;
        begin += bytesRead;

        bytesRead = pt_read_bytes(begin, end, data.data);
        if (bytesRead < 0) return -1;
        begin += bytesRead;

        return std::distance(begin, end);
    }

    ptrdiff_t serialize_pts_login_start(const pts_login_start &data, std::vector<char> &buffer) {
        ptrdiff_t size = 0, bytesWritten;

        bytesWritten = pt_write_varint(buffer, 0x00);
        if (bytesWritten < 0) return -1;
        size += bytesWritten;

        bytesWritten = pt_write_string(buffer, data.username);
        if (bytesWritten < 0) return -1;
        size += bytesWritten;

        bytesWritten = pt_write_uuid(buffer, data.playerUUID);
        if (bytesWritten < 0) return -1;
        size += bytesWritten;

        return size;
    }

    ptrdiff_t
    deserialize_pts_login_start(pts_login_start &data, const std::vector<char>::iterator &begin, const std::vector<char>::iterator &end) {
        ptrdiff_t bytesRead;
        auto it = begin;

        bytesRead = pt_read_string(it, end, data.username);
        if (bytesRead < 0) return -1;
        it += bytesRead;

        it += 1; // ?? why there's 01h ?
        bytesRead = pt_read_uuid(it, end, data.playerUUID);
        if (bytesRead < 0) return -1;

        return std::distance(begin, end);
    }

    ptrdiff_t serialize_pts_login_encryption(const pts_login_encryption_begin &data, std::vector<char> &buffer) {
        ptrdiff_t size = 0, bytesWritten;

        bytesWritten = pt_write_varint(buffer, 0x01);
        if (bytesWritten < 0) return -1;
        size += bytesWritten;


        bytesWritten = pt_write_bytes(buffer, data.sharedSecret);
        if (bytesWritten < 0) return -1;
        size += bytesWritten;

        bytesWritten = pt_write_bytes(buffer, data.verifyToken);
        if (bytesWritten < 0) return -1;
        size += bytesWritten;

        return size;
    }

    ptrdiff_t deserialize_pts_login_encryption_begin(
            pts_login_encryption_begin &data,
            const std::vector<char>::iterator &begin,
            const std::vector<char>::iterator &end) {
        ptrdiff_t bytesRead;
        auto it = begin;

        bytesRead = pt_read_bytes(it, end, data.sharedSecret);
        if (bytesRead < 0) return -1;
        it += bytesRead;

        bytesRead = pt_read_bytes(it, end, data.verifyToken);
        if (bytesRead < 0) return -1;
        //it += bytesRead;

        return std::distance(it, end);
    }

    ptrdiff_t serialize_ptc_login_success(const ptc_login_success &data, std::vector<char> &buffer) {
        ptrdiff_t size = 0, bytesWritten;

        bytesWritten = pt_write_varint(buffer, 0x02);
        if (bytesWritten < 0) return -1;
        size += bytesWritten;

        bytesWritten = pt_write_uuid(buffer, data.uuid);
        if (bytesWritten < 0) return -1;
        size += bytesWritten;

        bytesWritten = pt_write_string(buffer, data.username);
        if (bytesWritten < 0) return -1;
        size += bytesWritten;

        bytesWritten = serialize_properties(data.properties, buffer);
        if (bytesWritten < 0) return -1;
        size += bytesWritten;

        return size;
    }

/*

    ptrdiff_t deserialize_ptc_login_success(std::vector<char>::iterator &begin,
                                         const std::vector<char>::iterator &end,
                                         ptc_login_success &data) {
        ptrdiff_t bytesRead;

        bytesRead = pt_read_uuid(begin, end, data.uuid);
        if (bytesRead < 0) return -1;
        begin += bytesRead;

        bytesRead = pt_read_string(begin, end, data.username);
        if (bytesRead < 0) return -1;
        begin += bytesRead;

        property_t property;
        while (begin != end) { // Assuming properties are last in the buffer
            bytesRead = pt_read_property(begin, end, property);
            if (bytesRead < 0) return -1;
            begin += bytesRead;
            data.properties.push_back(property);
        }

        return bytesRead;
    }*/

    ptrdiff_t serialize_pts_login_plugin_response(const pts_login_login_plugin_response &data, std::vector<char> &buffer) {
        ptrdiff_t size = 0, bytesWritten;

        bytesWritten = pt_write_varint(buffer, 0x04);
        if (bytesWritten < 0) return -1;
        size += bytesWritten;

        bytesWritten = pt_write_varint(buffer, data.messageId);
        if (bytesWritten < 0) return -1;
        size += bytesWritten;

        if (!data.data.empty()) {
            bytesWritten = pt_write_bytes(buffer, data.data);
            if (bytesWritten < 0) return -1;
            size += bytesWritten;
        }

        return size;
    }

    ptrdiff_t deserialize_pts_login_plugin_response(std::vector<char>::iterator &begin,
                                                    const std::vector<char>::iterator &end,
                                                    pts_login_login_plugin_response &data) {
        ptrdiff_t bytesRead;

        bytesRead = pt_read_varint(begin, end, data.messageId);
        if (bytesRead < 0) return -1;
        begin += bytesRead;

        if (begin != end) { // Assuming data is the last element in buffer.
            bytesRead = pt_read_bytes(begin, end, data.data);
            if (bytesRead < 0) return -1;
            begin += bytesRead;
        }

        return std::distance(begin, end);
    }

    ptrdiff_t serialize_pts_login_acknowledged(const pts_login_login_acknowledged &data, std::vector<char> &buffer) {
        // No members to serialize
        return 0;
    }

    ptrdiff_t deserialize_pts_login_acknowledged(std::vector<char>::iterator &begin,
                                                 const std::vector<char>::iterator &end,
                                                 pts_login_login_acknowledged &data) {
        // No members to deserialize
        return 0;
    }
}