import { RNOHPackage } from '@rnoh/react-native-openharmony';
import { AnyThreadTurboModuleFactory, AnyThreadTurboModule } from '@rnoh/react-native-openharmony/ts';
import { WorkerTurboModuleContext } from '@rnoh/react-native-openharmony/src/main/ets/RNOH/RNOHContext';
import { RNRSAModule } from './RNRSAModule';
import { RNRSAKeychainModule } from './RNRSAKeychainModule';

class RNRSAModulesFactory extends AnyThreadTurboModuleFactory  {
  createTurboModule(name: string): AnyThreadTurboModule  | null {
    if (name === 'RNRSA') {
      return new RNRSAModule(this.ctx);
    }
    if (name === 'RNRSAKeychain') {
      return new RNRSAKeychainModule(this.ctx);
    }
    return null;
  }

  hasTurboModule(name: string): boolean {
    return name === 'RNRSA' || name === 'RNRSAKeychain';
  }
}

export class RNRSAPackage extends RNOHPackage {
  createAnyThreadTurboModuleFactory(ctx: WorkerTurboModuleContext): AnyThreadTurboModuleFactory {
    return new RNRSAModulesFactory(ctx);
  }
}