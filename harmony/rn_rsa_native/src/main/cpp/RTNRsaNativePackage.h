#pragma once

#include "RNOH/generated/BaseReactNativeRsaNativePackage.h"

namespace rnoh {

class RTNRsaNativePackage : public BaseReactNativeRsaNativePackage {
    using Super = BaseReactNativeRsaNativePackage;

public:
    RTNRsaNativePackage(Package::Context ctx) : Super(ctx) {}
};

}