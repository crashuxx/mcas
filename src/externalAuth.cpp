#include <curl/curl.h>
#include <cjson/cJSON.h>
#include "externalAuth.h"

namespace mcsa {

    size_t write_data(void *ptr, size_t size, size_t nmemb, std::vector<char> *data) {
        size_t n = (size * nmemb);

        unsigned long free = data->capacity() - data->size();
        if (free < n) {
            data->reserve(data->size() + n);
        }

#ifdef DEBUG
        fprintf(stderr, "data at %p size=%ld nmemb=%ld\n", ptr, size, nmemb);
#endif

        std::copy((char *) ptr, ((char *) ptr + n), std::back_inserter(*data));

        return size * nmemb;
    }

    std::vector<char> retrieveAccountInformationJson(const std::string &username, const std::string &hash) {
        CURL *curl;
        CURLcode res;
        std::vector<char> buffer;
        buffer.reserve(1024 * 8);

        curl = curl_easy_init();
        if (!curl) {
            buffer.resize(0);
            fprintf(stderr, "Failed to initialize cURL");
            return buffer;
        }

        std::string url = "https://sessionserver.mojang.com/session/minecraft/hasJoined?username=" + username + "&serverId=" + hash;
        curl_easy_setopt(curl, CURLOPT_URL, url.data());
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            buffer.resize(0);
        }

        curl_easy_cleanup(curl);

        buffer.shrink_to_fit();
        return buffer;
    }

    accountData_t *external_hasJoined(const std::string &username, const std::string &hash) {
        const std::vector<char> &data = retrieveAccountInformationJson(username, hash);

        if (data.empty()) {
            fprintf(stderr, "Error no data\n");
            return nullptr;
        }

        cJSON *json_data = cJSON_ParseWithLength(data.data(), data.size());
        if (json_data == nullptr) {
            const char *error = cJSON_GetErrorPtr();
            fprintf(stderr, "Error parsing json:\n %s\n", error);
            return nullptr;
        }

        auto *accountData = new accountData_t;

        cJSON *id = cJSON_GetObjectItemCaseSensitive(json_data, "id");
        if (!cJSON_IsString(id)) {
            delete accountData;
            cJSON_free(json_data);

            fprintf(stderr, "Error id not string\n");
            return nullptr;
        }
        accountData->id = id->valuestring;

        cJSON *name = cJSON_GetObjectItemCaseSensitive(json_data, "name");
        if (!cJSON_IsString(name)) {
            delete accountData;
            cJSON_free(json_data);

            fprintf(stderr, "Error name not string\n");
            return nullptr;
        }
        accountData->name = name->valuestring;

        accountData->id.resize(32);
        /*//11111111-2222-3333-4444-555555555555
        accountData->name.insert(8, "-");
        accountData->name.insert(13, "-");
        accountData->name.insert(18, "-");
        accountData->name.insert(23, "-");*/

        cJSON_free(json_data);
        return accountData;
    }

}