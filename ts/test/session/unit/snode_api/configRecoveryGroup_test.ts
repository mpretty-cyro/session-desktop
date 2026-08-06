import chai from 'chai';
import { beforeEach, describe } from 'mocha';
import Sinon from 'sinon';
import { GroupPubkeyType, PubkeyType } from 'libsession_util_nodejs';

import { ConfigRecovery } from '../../../../session/apis/snode_api/configRecovery';
import {
  MetaGroupWrapperActions,
  UserGroupsWrapperActions,
} from '../../../../webworker/workers/browser/libsession_worker_interface';
import { LibSessionUtil } from '../../../../session/utils/libsession/libsession_utils';
import { MessageSender } from '../../../../session/sending/MessageSender';
import { UserUtils } from '../../../../session/utils';
import {
  DeleteHashesFromGroupNodeSubRequest,
  StoreGroupInfoSubRequest,
  StoreGroupMembersSubRequest,
} from '../../../../session/apis/snode_api/SnodeRequestTypes';
import { TestUtils } from '../../../test-utils';

const { expect } = chai;

/**
 * Group recovery — the vectors that were blocked on the wrapper until v0.6.20 exposed
 * `pushForRecovery()` and `activeHashesByConfig()`: V16, V16a, V16b, V19, V20, V21.
 *
 * The user-path vectors are in configRecovery_test.ts and are NOT repeated here. What is specific
 * to groups is: which sub-config a hash belongs to (GroupKeys cannot be put back), and whether we
 * are an admin or a member (a member cannot delete).
 *
 * ON "ASSERTS THAT X DOES NOT HAPPEN" TESTS — same rule as the user file. Every absence assertion
 * below is also satisfied by the path dying early, so each carries something proving it reached the
 * decision. Where a vector's own premise is "it stops at a guard", the reachability anchor is the
 * paired positive test using the SAME fixture, named in the test.
 */

const INFO_HASH = 'infohash1';
const MEMBER_HASH = 'memberhash1';
const KEYS_HASH = 'keyshash1';

describe('ConfigRecovery (groups)', () => {
  let groupPk: GroupPubkeyType;
  let us: PubkeyType;
  let sendStub: Sinon.SinonStub;

  /** a clean group we are an ADMIN of, holding one hash in each of the three sub-configs */
  function stubGroup({
    secretKey = new Uint8Array(64).fill(7) as any,
    authData = null as any,
    kicked = false,
    destroyed = false,
    needsPush = false,
    infoHashes = [INFO_HASH],
    memberHashes = [MEMBER_HASH],
    keysHashes = [KEYS_HASH],
    infoParts = [new Uint8Array([1])],
    memberParts = [new Uint8Array([2])],
    infoObsolete = [] as Array<string>,
    memberObsolete = [] as Array<string>,
  } = {}) {
    Sinon.stub(UserGroupsWrapperActions, 'getGroup').resolves({
      pubkeyHex: groupPk,
      secretKey,
      authData,
      kicked,
      destroyed,
      name: 'g',
      invitePending: false,
    } as any);
    Sinon.stub(MetaGroupWrapperActions, 'needsPush').resolves(needsPush);
    Sinon.stub(MetaGroupWrapperActions, 'activeHashesByConfig').resolves({
      groupInfo: infoHashes,
      groupMember: memberHashes,
      groupKeys: keysHashes,
    });
    Sinon.stub(MetaGroupWrapperActions, 'pushForRecovery').resolves({
      groupInfo: { data: infoParts, seqno: 5, hashes: infoObsolete, namespace: 12 },
      groupMember: { data: memberParts, seqno: 5, hashes: memberObsolete, namespace: 13 },
    } as any);
  }

  function allSubRequestsSent() {
    return sendStub.getCalls().flatMap(c => c.args[0].sortedSubRequests as Array<unknown>);
  }

  function infoStoresSent() {
    return allSubRequestsSent().filter(r => r instanceof StoreGroupInfoSubRequest);
  }

  function memberStoresSent() {
    return allSubRequestsSent().filter(r => r instanceof StoreGroupMembersSubRequest);
  }

  function deleteRequestSent() {
    return allSubRequestsSent().find(
      (r): r is DeleteHashesFromGroupNodeSubRequest =>
        r instanceof DeleteHashesFromGroupNodeSubRequest
    );
  }

  beforeEach(() => {
    TestUtils.stubWindowLog();
    ConfigRecovery.resetForTesting();
    us = TestUtils.generateFakePubKeyStr();
    groupPk = TestUtils.generateFakeClosedGroupV2PkStr();
    Sinon.stub(UserUtils, 'getOurPubKeyStrFromCache').returns(us);
    Sinon.stub(UserUtils, 'isUsFromCache').callsFake(pk => pk === us);
    Sinon.stub(LibSessionUtil, 'saveDumpsToDb').resolves();
    sendStub = Sinon.stub(MessageSender, 'sendEncryptedDataToSnode').callsFake(
      async ({ sortedSubRequests }: any) =>
        sortedSubRequests.map(() => ({ code: 200, body: { hash: 'newhash' } })) as any
    );
  });

  afterEach(() => {
    Sinon.restore();
  });

  function detectMissing(hashes: Array<string>) {
    ConfigRecovery.recordDetection(groupPk, { status: 'conclusive', missingHashes: hashes });
  }

  it('V19: a missing GroupInfo hash is re-stored, and GroupKeys is not flagged expired', async () => {
    // The vector's point is that a missing groupInfo hash says nothing about the keys. An
    // implementation that treats "any group hash missing" as "the group is gone" passes nothing
    // else in this file and fails here.
    stubGroup();
    detectMissing([INFO_HASH]);
    ConfigRecovery.markLocalStateLevelWithSwarm(groupPk);

    const ran = await ConfigRecovery.recoverIfNeeded(groupPk);

    expect(ran, 'the group config was put back').to.be.true;
    expect(infoStoresSent().length, 'groupInfo re-stored').to.be.eq(1);
    expect(
      memberStoresSent().length,
      'and groupMember was NOT, it claimed no missing hash'
    ).to.be.eq(0);
  });

  it('V16a: one GroupKeys hash missing while another is PRESENT — no re-store, group not expired', async () => {
    // Read with V16 below: a keys hash cannot be put back by anyone but an admin rekey, so the
    // correct behaviour is to report and settle, NOT to attempt a store that would fail.
    stubGroup({ keysHashes: [KEYS_HASH, 'keyshash2'] });
    detectMissing([KEYS_HASH]);
    ConfigRecovery.markLocalStateLevelWithSwarm(groupPk);

    const ran = await ConfigRecovery.recoverIfNeeded(groupPk);

    expect(ran, 'nothing was restorable').to.be.false;
    expect(sendStub.called, 'and crucially nothing was SENT — a keys message cannot be re-emitted')
      .to.be.false;
  });

  it('V16: EVERY GroupKeys hash missing — still no re-store attempted', async () => {
    stubGroup();
    detectMissing([KEYS_HASH]);
    ConfigRecovery.markLocalStateLevelWithSwarm(groupPk);

    const ran = await ConfigRecovery.recoverIfNeeded(groupPk);

    expect(ran).to.be.false;
    expect(sendStub.called, 'no store for a config that cannot be re-emitted').to.be.false;
  });

  it('V16b: the device holds NO GroupKeys hashes at all, so no keys question was asked', async () => {
    // Distinct from V16: there, the keys hashes exist and are gone. Here we never had any, so a
    // missing groupInfo hash must still be recovered normally rather than the absence of keys
    // hashes being read as "the keys are missing".
    stubGroup({ keysHashes: [] });
    detectMissing([INFO_HASH]);
    ConfigRecovery.markLocalStateLevelWithSwarm(groupPk);

    const ran = await ConfigRecovery.recoverIfNeeded(groupPk);

    expect(ran, 'holding no keys hashes must not block an unrelated recovery').to.be.true;
    expect(infoStoresSent().length).to.be.eq(1);
  });

  it('V20: a non-admin MEMBER re-stores a clean GroupInfo whose hash is missing', async () => {
    // The trap this vector exists for is asserting the store is skipped for a member. It is not:
    // a member's subaccount token carries Read+Write, and this is the whole point of member-driven
    // recovery. Assert it SUCCEEDS.
    stubGroup({ secretKey: null, authData: new Uint8Array(100).fill(3) });
    detectMissing([INFO_HASH]);
    ConfigRecovery.markLocalStateLevelWithSwarm(groupPk);

    const ran = await ConfigRecovery.recoverIfNeeded(groupPk);

    expect(ran, 'a member CAN put its own copy back').to.be.true;
    expect(infoStoresSent().length, 'the store went out').to.be.eq(1);
  });

  it('V21: a member with an EMPTY obsolete-hash list still succeeds, and issues no delete', async () => {
    // Two traps in one vector. push() hands the superseded hashes back only if !is_readonly(), so
    // an empty list is EXPECTED for a member — asserting a non-empty one would be asserting a bug.
    // And a member could not delete anyway: its token has no Delete permission.
    stubGroup({ secretKey: null, authData: new Uint8Array(100).fill(3), infoObsolete: [] });
    detectMissing([INFO_HASH]);
    ConfigRecovery.markLocalStateLevelWithSwarm(groupPk);

    const ran = await ConfigRecovery.recoverIfNeeded(groupPk);

    expect(ran, 'the re-store still succeeds').to.be.true;
    expect(
      infoStoresSent().length,
      'proving we got past the store, not that we never tried'
    ).to.be.eq(1);
    expect(deleteRequestSent(), 'and no delete is attempted').to.be.undefined;
  });

  it('V21 (the gate itself): a MEMBER never deletes, even given a non-empty obsolete list', async () => {
    // The test above cannot see this rule. Its fixture has an EMPTY obsolete list, so "no delete"
    // is true there whether the admin check exists or not — found by mutation: removing the check
    // left that test green. push() should never hand a member a non-empty list, so this state is
    // not reachable through the wrapper today; the check is what stops it becoming a 401 storm if
    // that ever changes. Asserting it needs a fixture the real path cannot produce, which is the
    // point: an unreachable state is exactly what a defence-in-depth check is for.
    stubGroup({
      secretKey: null,
      authData: new Uint8Array(100).fill(3),
      infoObsolete: ['oldinfo1'],
    });
    detectMissing([INFO_HASH]);
    ConfigRecovery.markLocalStateLevelWithSwarm(groupPk);

    const ran = await ConfigRecovery.recoverIfNeeded(groupPk);

    expect(ran, 'the re-store still succeeds').to.be.true;
    expect(
      infoStoresSent().length,
      'and we got past the store rather than stopping short'
    ).to.be.eq(1);
    expect(deleteRequestSent(), 'but a member has no Delete permission, so no delete goes out').to
      .be.undefined;
  });

  it('V21 counterpart: an ADMIN with a non-empty obsolete list DOES delete', async () => {
    // The reachability control for the assertion above: without this, "no delete" would also pass
    // against a group delete path that was never wired at all.
    stubGroup({ infoObsolete: ['oldinfo1'] });
    detectMissing([INFO_HASH]);
    ConfigRecovery.markLocalStateLevelWithSwarm(groupPk);

    await ConfigRecovery.recoverIfNeeded(groupPk);

    expect(
      deleteRequestSent()?.messageHashes,
      'the admin prunes what it superseded'
    ).to.have.members(['oldinfo1']);
  });

  it('a KICKED group is not re-stored', async () => {
    stubGroup({ kicked: true });
    detectMissing([INFO_HASH]);
    ConfigRecovery.markLocalStateLevelWithSwarm(groupPk);

    const ran = await ConfigRecovery.recoverIfNeeded(groupPk);

    expect(ran).to.be.false;
    expect(sendStub.called, 'we are not entitled to write to this swarm any more').to.be.false;
  });

  it('a DESTROYED group is not re-stored — kicked is FALSE in that case', async () => {
    // Deliberately separate from the kicked test. libsession sets kicked=false when a group was
    // destroyed, so an implementation checking only `kicked` passes the test above and fails here.
    stubGroup({ kicked: false, destroyed: true });
    detectMissing([INFO_HASH]);
    ConfigRecovery.markLocalStateLevelWithSwarm(groupPk);

    const ran = await ConfigRecovery.recoverIfNeeded(groupPk);

    expect(ran).to.be.false;
    expect(sendStub.called).to.be.false;
  });

  it('a group with pending changes is not re-stored', async () => {
    stubGroup({ needsPush: true });
    detectMissing([INFO_HASH]);
    ConfigRecovery.markLocalStateLevelWithSwarm(groupPk);

    const ran = await ConfigRecovery.recoverIfNeeded(groupPk);

    expect(ran).to.be.false;
    expect(sendStub.called, 'GroupSync will push it under a new hash anyway').to.be.false;
  });

  it('a group swarm not level with local state is not recovered', async () => {
    stubGroup();
    detectMissing([INFO_HASH]);
    // deliberately NOT marking level

    const ran = await ConfigRecovery.recoverIfNeeded(groupPk);

    expect(ran).to.be.false;
    expect(sendStub.called).to.be.false;
  });

  it('both sub-configs are re-stored when both claim a missing hash', async () => {
    stubGroup();
    detectMissing([INFO_HASH, MEMBER_HASH]);
    ConfigRecovery.markLocalStateLevelWithSwarm(groupPk);

    const ran = await ConfigRecovery.recoverIfNeeded(groupPk);

    expect(ran).to.be.true;
    expect(infoStoresSent().length).to.be.eq(1);
    expect(memberStoresSent().length).to.be.eq(1);
  });

  it('the in-flight guard: a second round for the same swarm while one is running is refused', async () => {
    // Without this, `void`-ing the call in the poller means the next poll starts a second round
    // over hashes the first has not settled yet — duplicate stores aimed at the swarm already
    // being repaired.
    stubGroup();
    detectMissing([INFO_HASH]);
    ConfigRecovery.markLocalStateLevelWithSwarm(groupPk);

    let releaseSend: () => void = () => {};
    const blocked = new Promise<void>(resolve => {
      releaseSend = resolve;
    });
    sendStub.callsFake(async ({ sortedSubRequests }: any) => {
      await blocked;
      return sortedSubRequests.map(() => ({ code: 200, body: { hash: 'newhash' } }));
    });

    const first = ConfigRecovery.recoverIfNeeded(groupPk);

    // Let the first round get as far as the send before starting the second. It awaits the wrapper
    // several times on the way, so without this the second call races it to an earlier await and
    // the assertion below would be measuring the wrong moment.
    const flush = () =>
      new Promise<void>(resolve => {
        setTimeout(resolve, 0);
      });
    while (!sendStub.called) {
      // eslint-disable-next-line no-await-in-loop
      await flush();
    }

    // the first round is now parked inside the send, so this one must be turned away
    const second = await ConfigRecovery.recoverIfNeeded(groupPk);

    expect(second, 'the overlapping round is refused').to.be.false;
    expect(sendStub.callCount, 'and it sent nothing — one round is in flight, not two').to.be.eq(1);

    releaseSend();
    expect(await first, 'the original round still completes normally').to.be.true;
  });

  it('the in-flight guard releases after a FAILING round, or the swarm is withdrawn forever', async () => {
    // The guard must clear on the failure path too. A marker that leaks there would be a permanent
    // exclusion of exactly the swarm that needs repairing.
    stubGroup();
    detectMissing([INFO_HASH]);
    ConfigRecovery.markLocalStateLevelWithSwarm(groupPk);
    sendStub.rejects(new Error('network gone'));

    expect(await ConfigRecovery.recoverIfNeeded(groupPk), 'first round fails').to.be.false;

    // same swarm, a later round must still be admitted
    sendStub.callsFake(async ({ sortedSubRequests }: any) =>
      sortedSubRequests.map(() => ({ code: 200, body: { hash: 'newhash' } }))
    );
    ConfigRecovery.setNowForTesting(() => Date.now() + 60 * 60 * 1000);
    detectMissing([INFO_HASH]);

    expect(
      await ConfigRecovery.recoverIfNeeded(groupPk),
      'the guard released, so the retry is admitted'
    ).to.be.true;
  });
});
