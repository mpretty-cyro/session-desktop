import chai from 'chai';
import { beforeEach, describe } from 'mocha';
import Sinon from 'sinon';
import { GroupPubkeyType } from 'libsession_util_nodejs';

import { ConfigRecoveryForceRekey } from '../../../../session/apis/snode_api/configRecoveryForceRekey';
import { ConfigRecovery } from '../../../../session/apis/snode_api/configRecovery';
import {
  MetaGroupWrapperActions,
  UserGroupsWrapperActions,
} from '../../../../webworker/workers/browser/libsession_worker_interface';
import { LibSessionUtil } from '../../../../session/utils/libsession/libsession_utils';
import { GroupSync } from '../../../../session/utils/job_runners/jobs/GroupSyncJob';
import { TestUtils } from '../../../test-utils';

const { expect } = chai;

/**
 * The force rekey — the only irreversible, universally visible write in config recovery.
 *
 * Every assertion below is about NOT doing it, which makes them all vulnerable to passing because
 * the path died early rather than because a rule held. Each therefore starts from a fixture that
 * WOULD rekey, and changes exactly one thing; the first test proves that fixture actually rekeys,
 * so every later refusal is measured against a known-live baseline.
 */
describe('ConfigRecovery force rekey', () => {
  let groupPk: GroupPubkeyType;
  let rekeyStub: Sinon.SinonStub;
  let backfillFailedStub: Sinon.SinonStub;

  /** the state in which a rekey IS warranted: admin, keys all gone, no bytes, backfill tried */
  function stubWarranted({
    secretKey = new Uint8Array(64).fill(7) as any,
    kicked = false,
    destroyed = false,
    keysHashes = ['keyshash1'],
    retained = {} as Record<string, Uint8Array>,
    backfillFailed = true,
  } = {}) {
    Sinon.stub(UserGroupsWrapperActions, 'getGroup').resolves({
      pubkeyHex: groupPk,
      secretKey,
      authData: null,
      kicked,
      destroyed,
      name: 'g',
      invitePending: false,
    } as any);
    Sinon.stub(MetaGroupWrapperActions, 'activeHashesByConfig').resolves({
      groupInfo: [],
      groupMember: [],
      groupKeys: keysHashes,
    });
    Sinon.stub(MetaGroupWrapperActions, 'activeKeyMessages').resolves(retained);
    backfillFailedStub = Sinon.stub(ConfigRecovery, 'keysBackfillHasFailedFor').returns(
      backfillFailed
    );
  }

  beforeEach(() => {
    TestUtils.stubWindowLog();
    ConfigRecoveryForceRekey.resetForTesting();
    groupPk = TestUtils.generateFakeClosedGroupV2PkStr();
    rekeyStub = Sinon.stub(MetaGroupWrapperActions, 'keyRekey').resolves(undefined as any);
    Sinon.stub(LibSessionUtil, 'saveDumpsToDb').resolves();
    Sinon.stub(GroupSync, 'queueNewJobIfNeeded').resolves();
  });

  afterEach(() => {
    Sinon.restore();
  });

  const fresh = { levelWithSwarmThisPoll: true };

  it('rekeys when nothing here can restore the keys — the baseline every refusal is measured against', async () => {
    stubWarranted();

    const did = await ConfigRecoveryForceRekey.forceRekeyIfPossible(groupPk, fresh);

    expect(did, 'the fixture genuinely rekeys').to.be.true;
    expect(rekeyStub.calledOnceWith(groupPk)).to.be.true;
    expect(
      (LibSessionUtil.saveDumpsToDb as unknown as Sinon.SinonStub).calledWith(groupPk),
      'and the new generation is persisted, or it dies with the process'
    ).to.be.true;
    expect(
      (GroupSync.queueNewJobIfNeeded as unknown as Sinon.SinonStub).called,
      'and queued for push, or nobody else ever sees it'
    ).to.be.true;
  });

  it('REFUSES a stale members view, even though everything else warrants it', async () => {
    // The rekey encrypts to this device's view of the members. If that view is behind, whoever was
    // added since is silently left out — and this fires precisely on devices whose config state is
    // known to be degraded, so "behind" is the expected condition rather than the unlucky one.
    stubWarranted();

    const did = await ConfigRecoveryForceRekey.forceRekeyIfPossible(groupPk, {
      levelWithSwarmThisPoll: false,
    });

    expect(did).to.be.false;
    expect(rekeyStub.called, 'nothing minted from a members list we know may be behind').to.be
      .false;
  });

  it('REFUSES when a backfill has never run', async () => {
    // "We hold no bytes" cannot distinguish "a backfill ran and found nothing" from "no backfill has
    // ever run" — identical on a fresh install, a restored backup, or before the first poll
    // completes. Only the first justifies this.
    stubWarranted({ backfillFailed: false });

    const did = await ConfigRecoveryForceRekey.forceRekeyIfPossible(groupPk, fresh);

    expect(did).to.be.false;
    expect(backfillFailedStub.called, 'PREMISE: it actually consulted the record').to.be.true;
    expect(rekeyStub.called).to.be.false;
  });

  it('REFUSES when one keys message is still recoverable', async () => {
    // A single surviving keys hash still lets a new device in, so the group is not stuck.
    stubWarranted({
      keysHashes: ['keyshash1', 'keyshash2'],
      retained: { keyshash2: new Uint8Array([1]) },
    });

    expect(await ConfigRecoveryForceRekey.forceRekeyIfPossible(groupPk, fresh)).to.be.false;
    expect(rekeyStub.called).to.be.false;
  });

  it('REFUSES for a member — only an admin can mint a key', async () => {
    stubWarranted({ secretKey: null });

    expect(await ConfigRecoveryForceRekey.forceRekeyIfPossible(groupPk, fresh)).to.be.false;
    expect(rekeyStub.called).to.be.false;
  });

  it('REFUSES for a kicked or destroyed group', async () => {
    stubWarranted({ destroyed: true });

    expect(await ConfigRecoveryForceRekey.forceRekeyIfPossible(groupPk, fresh)).to.be.false;
    expect(rekeyStub.called).to.be.false;
  });

  it('rekeys a group ONCE — a second call in the same session is refused', async () => {
    // Without this, every poll that still sees the old preconditions mints another generation, and
    // each one is a write every member on every version has to process.
    stubWarranted();

    expect(await ConfigRecoveryForceRekey.forceRekeyIfPossible(groupPk, fresh)).to.be.true;
    expect(await ConfigRecoveryForceRekey.forceRekeyIfPossible(groupPk, fresh)).to.be.false;
    expect(rekeyStub.callCount, 'exactly one generation minted').to.be.eq(1);
  });
});
