//
// Created by drops on 5/7/24.
//

#ifndef MCAS_LOGIN_PLAY_H
#define MCAS_LOGIN_PLAY_H

#include "types.h"

namespace mcas::protocol {

    struct LoginPlay {
        int32_t entityID;
        bool isHardcore;
        std::vector<std::string> dimensionNames;
        varint_t maxPlayers;
        varint_t viewDistance;
        varint_t simulationDistance;
        bool reducedDebugInfo;
        bool enableRespawnScreen;
        bool doLimitedCrafting;
        std::string dimensionType;
        std::string dimensionName;
        int64_t hashedSeed;
        int8_t gameMode;
        int8_t previousGameMode;
        bool isDebug;
        bool isFlat;
        std::optional<std::string> deathDimensionName;
        std::optional<position_t> deathLocation;
        varint_t portalCooldown;
    };

}

#endif //MCAS_LOGIN_PLAY_H
