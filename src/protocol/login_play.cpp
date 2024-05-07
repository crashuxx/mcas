//
// Created by drops on 5/7/24.
//

#include <cassert>
#include "login_play.h"
#include "protocol.h"

namespace mcas::protocol {

    std::vector<char> serializeLoginPlay(const LoginPlay& loginPlay) {
        std::vector<char> buffer;

        pt_write_int32(buffer, loginPlay.entityID);
        pt_write_bool(buffer, loginPlay.isHardcore);

        pt_write_varint(buffer, loginPlay.dimensionName.size());
        for (const auto& dimensionName : loginPlay.dimensionNames) {
            pt_write_string(buffer, dimensionName);
        }

        pt_write_varint(buffer, loginPlay.maxPlayers);
        pt_write_varint(buffer, loginPlay.viewDistance);
        pt_write_varint(buffer, loginPlay.simulationDistance);
        pt_write_bool(buffer, loginPlay.reducedDebugInfo);
        pt_write_bool(buffer, loginPlay.enableRespawnScreen);
        pt_write_bool(buffer, loginPlay.doLimitedCrafting);
        pt_write_string(buffer, loginPlay.dimensionType);
        pt_write_string(buffer, loginPlay.dimensionName);
        pt_write_int64(buffer, loginPlay.hashedSeed);
        pt_write_int8(buffer, loginPlay.gameMode);
        pt_write_int8(buffer, loginPlay.previousGameMode);
        pt_write_bool(buffer, loginPlay.isDebug);
        pt_write_bool(buffer, loginPlay.isFlat);

        assert(loginPlay.deathDimensionName.has_value() == loginPlay.deathLocation.has_value());
        if (loginPlay.deathDimensionName.has_value()) {
            pt_write_bool(buffer, loginPlay.deathDimensionName.has_value());
            pt_write_string(buffer, loginPlay.deathDimensionName.value());
            pt_write_position_t(buffer, loginPlay.deathLocation.value());
        }

        pt_write_varint(buffer, loginPlay.portalCooldown);

        return buffer;
    }
}