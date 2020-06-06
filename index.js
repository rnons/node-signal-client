const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const _ = require('lodash');
const qrcode = require('qrcode-terminal');
const Promise = require('bluebird');
const events = require('events');

require('mkdirp').sync(process.cwd() + '/data');
global.window = global;
window.app = {};
app.getPath = function() {
  return process.cwd() + '/data/';
}
const signalDesktopRoot = path.resolve('node_modules', 'signal-desktop');
const signalPath = (script) => path.join(signalDesktopRoot, script);
const signalRequire = (script) => require(signalPath(script));

process.on('unhandledRejection', function (reason, p) {
  console.log("Possibly Unhandled Rejection at: Promise ", p, " reason: ", reason);
});
window.emitter = new events.EventEmitter();


window.setUnreadCount = function(count) {
  console.log('unread count:', count);
}
window.clearAttention = function() {
  // called when unreadcount is set to 0
}

window.filesize = require('filesize');

const auth = "-----BEGIN CERTIFICATE-----\nMIID7zCCAtegAwIBAgIJAIm6LatK5PNiMA0GCSqGSIb3DQEBBQUAMIGNMQswCQYD\nVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5j\naXNjbzEdMBsGA1UECgwUT3BlbiBXaGlzcGVyIFN5c3RlbXMxHTAbBgNVBAsMFE9w\nZW4gV2hpc3BlciBTeXN0ZW1zMRMwEQYDVQQDDApUZXh0U2VjdXJlMB4XDTEzMDMy\nNTIyMTgzNVoXDTIzMDMyMzIyMTgzNVowgY0xCzAJBgNVBAYTAlVTMRMwEQYDVQQI\nDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMR0wGwYDVQQKDBRP\ncGVuIFdoaXNwZXIgU3lzdGVtczEdMBsGA1UECwwUT3BlbiBXaGlzcGVyIFN5c3Rl\nbXMxEzARBgNVBAMMClRleHRTZWN1cmUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\nggEKAoIBAQDBSWBpOCBDF0i4q2d4jAXkSXUGpbeWugVPQCjaL6qD9QDOxeW1afvf\nPo863i6Crq1KDxHpB36EwzVcjwLkFTIMeo7t9s1FQolAt3mErV2U0vie6Ves+yj6\ngrSfxwIDAcdsKmI0a1SQCZlr3Q1tcHAkAKFRxYNawADyps5B+Zmqcgf653TXS5/0\nIPPQLocLn8GWLwOYNnYfBvILKDMItmZTtEbucdigxEA9mfIvvHADEbteLtVgwBm9\nR5vVvtwrD6CCxI3pgH7EH7kMP0Od93wLisvn1yhHY7FuYlrkYqdkMvWUrKoASVw4\njb69vaeJCUdU+HCoXOSP1PQcL6WenNCHAgMBAAGjUDBOMB0GA1UdDgQWBBQBixjx\nP/s5GURuhYa+lGUypzI8kDAfBgNVHSMEGDAWgBQBixjxP/s5GURuhYa+lGUypzI8\nkDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQB+Hr4hC56m0LvJAu1R\nK6NuPDbTMEN7/jMojFHxH4P3XPFfupjR+bkDq0pPOU6JjIxnrD1XD/EVmTTaTVY5\niOheyv7UzJOefb2pLOc9qsuvI4fnaESh9bhzln+LXxtCrRPGhkxA1IMIo3J/s2WF\n/KVYZyciu6b4ubJ91XPAuBNZwImug7/srWvbpk0hq6A6z140WTVSKtJG7EP41kJe\n/oF4usY5J7LPkxK3LWzMJnb5EIJDmRvyH8pyRwWg6Qm6qiGFaI4nL8QU4La1x2en\n4DGXRaLMPRwjELNgQPodR38zoCMuA8gHZfZYYoZ7D7Q1wNUiVHcxuFrEeBaYJbLE\nrwLV\n-----END CERTIFICATE-----\n";

const Attachments = signalRequire('app/attachments');

window.navigator = {
  onLine: true,
  userAgent: 'nodejs',
  appName: 'nodejs',
  hardwareConcurrency: 1
};

function now() {
  const date = new Date();
  return date.toJSON();
}

function logAtLevel(level, prefix, ...args) {
  console.log(prefix, now(), ...args);
}

window.log = {
  fatal: _.partial(logAtLevel, 'fatal', 'FATAL'),
  error: _.partial(logAtLevel, 'error', 'ERROR'),
  warn: _.partial(logAtLevel, 'warn', 'WARN '),
  info: _.partial(logAtLevel, 'info', 'INFO '),
  debug: _.partial(logAtLevel, 'debug', 'DEBUG'),
  trace: _.partial(logAtLevel, 'trace', 'TRACE')
};


const config = signalRequire('config/production');
//Needed to ask for devices, and not saved in production
const packageJson = signalRequire('package.json');
config.version = packageJson.version;

//FROM: preload.js
window.platform = process.platform;
window.getTitle = () => "";
window.getEnvironment = () => config.environment;
window.getAppInstance = () => config.appInstance;
window.getVersion = () => config.version;
window.getExpiration = () => config.buildExpiration;
window.getNodeVersion = () => config.node_version;
window.getHostName = () => config.hostname;
window.getServerTrustRoot = () => config.serverTrustRoot;
window.getServerPublicParams = () => config.serverPublicParams;
window.isBehindProxy = () => Boolean(config.proxyUrl);

//Added
window.setBadgeCount = count => "";
window.updateTrayIcon = window.updateTrayIcon = unreadCount => "";

//...

window.textsecure = signalRequire('ts/textsecure').default;

//adapted
window.WebAPI = window.textsecure.WebAPI.initialize({
  url: config.serverUrl,
  cdnUrlObject: {
    '0': config.cdn['0'],
    '2': config.cdn['2'],
  },
  certificateAuthority: auth,
  contentProxyUrl: "http://contentproxy.signal.org:443",
  proxyUrl: config.proxyUrl,
  version: config.version,
});

//...

window.isValidGuid = maybeGuid =>
  /^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/i.test(
    maybeGuid
  );
// https://stackoverflow.com/a/23299989
window.isValidE164 = maybeE164 => /^\+?[1-9]\d{1,14}$/.test(maybeE164);

window.normalizeUuids = (obj, paths, context) => {
  if (!obj) {
    return;
  }
  paths.forEach(path => {
    const val = _.get(obj, path);
    if (val) {
      if (!window.isValidGuid(val)) {
        window.log.warn(
          `Normalizing invalid uuid: ${val} at path ${path} in context "${context}"`
        );
      }
      _.set(obj, path, val.toLowerCase());
    }
  });
};

//...

const Signal = signalRequire('./js/modules/signal');
window.Signal = Signal.setup({
  Attachments,
  userDataPath: process.cwd() + '/data/',
  getRegionCode: () => window.storage.get('regionCode'),
  logger: window.log,
});

window.i18n = function(locale, messages) {
  return '';
}
//ENDFROM

window.PROTO_ROOT = signalDesktopRoot + '/protos';
// need this to avoid opaque origin error in indexeddb shim
window.location = {
  origin: "localhost"
}
window.XMLHttpRequest = require('xhr2');
window.moment = require('moment');
window.PQueue = require('p-queue').default
window._ = require('underscore');
window.Backbone = require('backbone');
const jQuery = require('jquery-deferred');
window.$ = jQuery;
window.Backbone.$ = jQuery;
window.Event = function (type) {
  this.type = type;
}

window.FileReader = function () {
  this.readAsArrayBuffer = (blob) => {
    this.result = blob;
    this.onload();
  }
}

const setGlobalIndexedDbShimVars = require('indexeddbshim');
setGlobalIndexedDbShimVars(); // 

window.btoa = function (str) {
  return new Buffer(str).toString('base64');
};

window.Whisper = {};
Whisper.Notifications = {};
Whisper.Notifications.remove = () => undefined;
Whisper.Notifications.where = () => undefined;
Whisper.Notifications.findWhere = () => undefined;
Whisper.events = _.clone(Backbone.Events);


//FROM: background.js

//For sending read receipts
Whisper.deliveryReceiptQueue = new window.PQueue({
  concurrency: 1,
});
Whisper.deliveryReceiptQueue.pause();
Whisper.deliveryReceiptBatcher = window.Signal.Util.createBatcher({
  wait: 500,
  maxSize: 500,
  processBatch: async items => {
    const bySource = _.groupBy(items, item => item.source || item.sourceUuid);
    const sources = Object.keys(bySource);

    for (let i = 0, max = sources.length; i < max; i += 1) {
      const source = sources[i];
      const timestamps = bySource[source].map(item => item.timestamp);

      try {
        const c = ConversationController.get(source);
        const { wrap, sendOptions } = ConversationController.prepareForSend(
          c.get('id')
        );
        // eslint-disable-next-line no-await-in-loop
        await wrap(
          textsecure.messaging.sendDeliveryReceipt(
            c.get('e164'),
            c.get('uuid'),
            timestamps,
            sendOptions
          )
        );
      } catch (error) {
        window.log.error(
          `Failed to send delivery receipt to ${source} for timestamps ${timestamps}:`,
          error && error.stack ? error.stack : error
        );
      }
    }
  },
});


//Needed for conversation sendMessage
let activeTimestamp = Date.now();
const ACTIVE_TIMEOUT = 15 * 1000;
window.isActive = () => {
  const now = Date.now();
  return now <= activeTimestamp + ACTIVE_TIMEOUT;
};

const { Errors, Message } = window.Signal.Types;
const {
  upgradeMessageSchema,
  loadAttachmentData,
  writeNewAttachmentData,
  deleteAttachmentData,
  doesAttachmentExist,
} = window.Signal.Migrations;

//ENDFROM

window.keyStore = {
  put: function (key, value) {
    fs.writeFileSync(process.cwd() + '/data/' + key, textsecure.utils.jsonThing(value));
    let item = new Item({
      id: key,
      value
    });
    item.save();
  },
  get: function (key, defaultValue) {
    try {
      let raw = fs.readFileSync(process.cwd() + '/data/' + key);
      if (typeof raw === "undefined") {
        return defaultValue;
      } else {
        return val = JSON.parse(raw);
      }
    } catch (e) {
      return defaultValue;
    }
  },
  remove: function (key) {
    try {
      fs.unlinkSync(process.cwd() + '/data/' + key);
    } catch (e) {

    }
  }
}

window.Backbone.sync = signalRequire('components/indexeddb-backbonejs-adapter/backbone-indexeddb').sync;

window.globalListeners = {}
window.getGuid = require('uuid/v4');

window.addEventListener = Whisper.events.on;

const WebCrypto = require("node-webcrypto-ossl");
window.crypto = new WebCrypto();

window.dcodeIO = {}
dcodeIO.Long = signalRequire('components/long/dist/Long');
dcodeIO.ProtoBuf = signalRequire('components/protobuf/dist/ProtoBuf');

dcodeIO.ProtoBuf.Util.fetch = (path, callback) => {
  fs.readFile(path, (err, data) => {
    if (err)
      callback(null);
    else
      callback("" + data);
  });
}

dcodeIO.ByteBuffer = require('bytebuffer');
signalRequire('js/reliable_trigger');
signalRequire('js/database');
signalRequire('js/storage');

signalRequire('js/signal_protocol_store');
signalRequire('js/libtextsecure');
signalRequire('js/delivery_receipts');
signalRequire('js/read_receipts');
signalRequire('js/read_syncs');
signalRequire('js/view_syncs');
window.libphonenumber = require('google-libphonenumber').PhoneNumberUtil.getInstance();
window.libphonenumber.PhoneNumberFormat = require('google-libphonenumber').PhoneNumberFormat;
signalRequire('js/libphonenumber-util');
signalRequire('js/models/messages');
signalRequire('js/models/conversations');
signalRequire('js/models/blockedNumbers');
signalRequire('js/expiring_messages');
signalRequire('js/expiring_tap_to_view_messages');

signalRequire('js/chromium');
signalRequire('ts/util/registration');
//  signalRequire('js/expire');
signalRequire('js/conversation_controller');
signalRequire('js/message_controller');
signalRequire('js/reactions');

signalRequire('js/wall_clock_listener');
signalRequire('js/rotate_signed_prekey_listener');
signalRequire('js/keychange_listener');

signalRequire('js/deletes');

window.sql = signalRequire('ts/sql/Server').default;
window.sqlChannels = signalRequire('app/sql_channel');

let Model = Backbone.Model.extend({
  database: Whisper.Database
});
let Item = Model.extend({
  storeName: 'items'
});

//FROM: background.js
let connectCount = 0;
let initialLoadComplete = false;

//...

Whisper.KeyChangeListener.init(textsecure.storage.protocol);
textsecure.storage.protocol.on('removePreKey', () => {
getAccountManager().refreshPreKeys();
});

let messageReceiver;
window.getSocketStatus = () => {
    if (messageReceiver) {
        return messageReceiver.getStatus();
    }
    return -1;
};
Whisper.events = _.clone(Backbone.Events);
let accountManager;
window.getAccountManager = () => {
  if (!accountManager) {
    const OLD_USERNAME = storage.get('number_id');
    const USERNAME = storage.get('uuid_id');
    const PASSWORD = storage.get('password');
    accountManager = new textsecure.AccountManager(
      USERNAME || OLD_USERNAME,
      PASSWORD
    );
    accountManager.addEventListener('registration', () => {
      const ourNumber = textsecure.storage.user.getNumber();
      const ourUuid = textsecure.storage.user.getUuid();
      const user = {
        regionCode: window.storage.get('regionCode'),
        ourNumber,
        ourUuid,
        ourConversationId: ConversationController.getConversationId(
        ourNumber || ourUuid
        ),
      };
      Whisper.events.trigger('userChanged', user);

      window.Signal.Util.Registration.markDone();
      window.log.info('dispatching registration event');
      Whisper.events.trigger('registration_done');
    });
  }
  return accountManager;
};
//ENDFROM


Whisper.events.on('unauthorized', function () {
  console.log('unauthorized!');
});
Whisper.events.on('reconnectTimer', function () {
  console.log('reconnect timer!');
});

//FROM: background.js
function onConfiguration(ev) {
  ev.confirm();

  const { configuration } = ev;
  const {
    readReceipts,
    typingIndicators,
    unidentifiedDeliveryIndicators,
    linkPreviews,
  } = configuration;

  storage.put('read-receipt-setting', readReceipts);

  if (
    unidentifiedDeliveryIndicators === true ||
    unidentifiedDeliveryIndicators === false
  ) {
    storage.put(
      'unidentifiedDeliveryIndicators',
      unidentifiedDeliveryIndicators
    );
  }

  if (typingIndicators === true || typingIndicators === false) {
    storage.put('typingIndicators', typingIndicators);
  }

  if (linkPreviews === true || linkPreviews === false) {
    storage.put('linkPreviews', linkPreviews);
  }
}

function onTyping(ev) {
  // Note: this type of message is automatically removed from cache in MessageReceiver

  const { typing, sender, senderUuid, senderDevice } = ev;
  const { groupId, started } = typing || {};

  // We don't do anything with incoming typing messages if the setting is disabled
  if (!storage.get('typingIndicators')) {
    return;
  }

  const conversation = ConversationController.get(
    groupId || sender || senderUuid
  );
  const ourUuid = textsecure.storage.user.getUuid();
  const ourNumber = textsecure.storage.user.getNumber();

  if (conversation) {
    // We drop typing notifications in groups we're not a part of
    if (
      !conversation.isPrivate() &&
      !conversation.hasMember(ourNumber || ourUuid)
    ) {
      window.log.warn(
        `Received typing indicator for group ${conversation.idForLogging()}, which we're not a part of. Dropping.`
      );
      return;
    }

//       conversation.notifyTyping({
//         isTyping: started,
//         sender,
//         senderUuid,
//         senderDevice,
//       });
  }
}

async function onStickerPack(ev) {
  ev.confirm();

  const packs = ev.stickerPacks || [];

  packs.forEach(pack => {
    const { id, key, isInstall, isRemove } = pack || {};

    if (!id || !key || (!isInstall && !isRemove)) {
      window.log.warn(
        'Received malformed sticker pack operation sync message'
      );
      return;
    }

    const status = window.Signal.Stickers.getStickerPackStatus(id);

    if (status === 'installed' && isRemove) {
      window.reduxActions.stickers.uninstallStickerPack(id, key, {
        fromSync: true,
      });
    } else if (isInstall) {
      if (status === 'downloaded') {
        window.reduxActions.stickers.installStickerPack(id, key, {
          fromSync: true,
        });
      } else {
        window.Signal.Stickers.downloadStickerPack(id, key, {
          finalStatus: 'installed',
          fromSync: true,
        });
      }
    }
  });
}

async function onContactReceived(ev) {
  const details = ev.contactDetails;

  if (
    details.number === textsecure.storage.user.getNumber() ||
    details.uuid === textsecure.storage.user.getUuid()
  ) {
    // special case for syncing details about ourselves
    if (details.profileKey) {
      window.log.info('Got sync message with our own profile key');
      storage.put('profileKey', details.profileKey);
    }
  }

  const c = new Whisper.Conversation({
    e164: details.number,
    uuid: details.uuid,
    type: 'private',
  });
  const validationError = c.validate();
  if (validationError) {
    window.log.error(
      'Invalid contact received:',
      Errors.toLogFormat(validationError)
    );
    return;
  }

  try {
    const conversation = await ConversationController.getOrCreateAndWait(
      details.number || details.uuid,
      'private'
    );
    let activeAt = conversation.get('active_at');

    // The idea is to make any new contact show up in the left pane. If
    //   activeAt is null, then this contact has been purposefully hidden.
    if (activeAt !== null) {
      activeAt = activeAt || Date.now();
    }

    if (details.profileKey) {
      const profileKey = window.Signal.Crypto.arrayBufferToBase64(
        details.profileKey
      );
      conversation.setProfileKey(profileKey);
    } else {
      conversation.dropProfileKey();
    }

    if (typeof details.blocked !== 'undefined') {
      const e164 = conversation.get('e164');
      if (details.blocked && e164) {
        storage.addBlockedNumber(e164);
      } else {
        storage.removeBlockedNumber(e164);
      }

      const uuid = conversation.get('uuid');
      if (details.blocked && uuid) {
        storage.addBlockedUuid(uuid);
      } else {
        storage.removeBlockedUuid(uuid);
      }
    }

    conversation.set({
      name: details.name,
      color: details.color,
      active_at: activeAt,
      inbox_position: details.inboxPosition,
    });

    // Update the conversation avatar only if new avatar exists and hash differs
    const { avatar } = details;
    if (avatar && avatar.data) {
      const newAttributes = await window.Signal.Types.Conversation.maybeUpdateAvatar(
        conversation.attributes,
        avatar.data,
        {
          writeNewAttachmentData,
          deleteAttachmentData,
          doesAttachmentExist,
        }
      );
      conversation.set(newAttributes);
    } else {
      const { attributes } = conversation;
      if (attributes.avatar && attributes.avatar.path) {
        await deleteAttachmentData(attributes.avatar.path);
      }
      conversation.set({ avatar: null });
    }

    window.Signal.Data.updateConversation(
      details.number || details.uuid,
      conversation.attributes
    );

    const { expireTimer } = details;
    const isValidExpireTimer = typeof expireTimer === 'number';
    if (isValidExpireTimer) {
      const sourceE164 = textsecure.storage.user.getNumber();
      const sourceUuid = textsecure.storage.user.getUuid();
      const receivedAt = Date.now();

      await conversation.updateExpirationTimer(
        expireTimer,
        sourceE164 || sourceUuid,
        receivedAt,
        { fromSync: true }
      );
    }

    if (details.verified) {
      const { verified } = details;
      const verifiedEvent = new Event('verified');
      verifiedEvent.verified = {
        state: verified.state,
        destination: verified.destination,
        destinationUuid: verified.destinationUuid,
        identityKey: verified.identityKey.toArrayBuffer(),
      };
      verifiedEvent.viaContactSync = true;
        await onVerified(verifiedEvent);
    }

//       const { appView } = window.owsDesktopApp;
//       if (appView && appView.installView && appView.installView.didLink) {
//         window.log.info(
//           'onContactReceived: Adding the message history disclaimer on link'
//         );
//         await conversation.addMessageHistoryDisclaimer();
//       }
  } catch (error) {
    window.log.error('onContactReceived error:', Errors.toLogFormat(error));
  }
}

async function onGroupReceived(ev) {
  const details = ev.groupDetails;
  const { id } = details;

  const conversation = await ConversationController.getOrCreateAndWait(
    id,
    'group'
  );

  const memberConversations = await Promise.all(
    (details.members || details.membersE164).map(member => {
      if (member.e164 || member.uuid) {
        return ConversationController.getOrCreateAndWait(
          member.e164 || member.uuid,
          'private'
        );
      }
      return ConversationController.getOrCreateAndWait(member, 'private');
    })
  );

  const members = memberConversations.map(c => c.get('id'));

  const updates = {
    name: details.name,
    members,
    color: details.color,
    type: 'group',
    inbox_position: details.inboxPosition,
  };

  if (details.active) {
    const activeAt = conversation.get('active_at');

    // The idea is to make any new group show up in the left pane. If
    //   activeAt is null, then this group has been purposefully hidden.
    if (activeAt !== null) {
      updates.active_at = activeAt || Date.now();
    }
    updates.left = false;
  } else {
    updates.left = true;
  }

  if (details.blocked) {
    storage.addBlockedGroup(id);
  } else {
    storage.removeBlockedGroup(id);
  }

  conversation.set(updates);

  // Update the conversation avatar only if new avatar exists and hash differs
  const { avatar } = details;
  if (avatar && avatar.data) {
    const newAttributes = await window.Signal.Types.Conversation.maybeUpdateAvatar(
      conversation.attributes,
      avatar.data,
      {
        writeNewAttachmentData,
        deleteAttachmentData,
        doesAttachmentExist,
      }
    );
    conversation.set(newAttributes);
  }

  window.Signal.Data.updateConversation(id, conversation.attributes);

//     const { appView } = window.owsDesktopApp;
//     if (appView && appView.installView && appView.installView.didLink) {
//       window.log.info(
//         'onGroupReceived: Adding the message history disclaimer on link'
//       );
//       await conversation.addMessageHistoryDisclaimer();
//     }
  const { expireTimer } = details;
  const isValidExpireTimer = typeof expireTimer === 'number';
  if (!isValidExpireTimer) {
    return;
  }

  const sourceE164 = textsecure.storage.user.getNumber();
  const sourceUuid = textsecure.storage.user.getUuid();
  const receivedAt = Date.now();
  await conversation.updateExpirationTimer(
    expireTimer,
    sourceE164 || sourceUuid,
    receivedAt,
    {
      fromSync: true,
    }
  );
}

// Descriptors
const getGroupDescriptor = group => ({
  type: Message.GROUP,
  id: group.id,
});

// Matches event data from `libtextsecure` `MessageReceiver::handleSentMessage`:
const getDescriptorForSent = ({ message, destination }) =>
  message.group
    ? getGroupDescriptor(message.group)
    : { type: Message.PRIVATE, id: destination };

// Matches event data from `libtextsecure` `MessageReceiver::handleDataMessage`:
const getDescriptorForReceived = ({ message, source, sourceUuid }) =>
  message.group
    ? getGroupDescriptor(message.group)
    : { type: Message.PRIVATE, id: source || sourceUuid };

// Received:
async function handleMessageReceivedProfileUpdate({
  data,
  confirm,
  messageDescriptor,
}) {
  const profileKey = data.message.profileKey.toString('base64');
  const sender = await ConversationController.getOrCreateAndWait(
    messageDescriptor.id,
    'private'
  );

  // Will do the save for us
  await sender.setProfileKey(profileKey);

  return confirm();
}

// Note: We do very little in this function, since everything in handleDataMessage is
//   inside a conversation-specific queue(). Any code here might run before an earlier
//   message is processed in handleDataMessage().
function onMessageReceived(event) {
    const { data, confirm } = event;

    const messageDescriptor = getDescriptorForReceived(data);

    const { PROFILE_KEY_UPDATE } = textsecure.protobuf.DataMessage.Flags;
    // eslint-disable-next-line no-bitwise
    const isProfileUpdate = Boolean(data.message.flags & PROFILE_KEY_UPDATE);
    if (isProfileUpdate) {
        return handleMessageReceivedProfileUpdate({
        data,
        confirm,
        messageDescriptor,
        });
    }

    const message = initIncomingMessage(data);

    const result = ConversationController.getOrCreate(
        messageDescriptor.id,
        messageDescriptor.type
    );

    if (messageDescriptor.type === 'private') {
        result.updateE164(data.source);
        if (data.sourceUuid) {
        result.updateUuid(data.sourceUuid);
        }
    }

    if (data.message.reaction) {
        const { reaction } = data.message;
        const reactionModel = Whisper.Reactions.add({
        emoji: reaction.emoji,
        remove: reaction.remove,
        targetAuthorE164: reaction.targetAuthorE164,
        targetAuthorUuid: reaction.targetAuthorUuid,
        targetTimestamp: reaction.targetTimestamp.toNumber(),
        timestamp: Date.now(),
        fromId: data.source || data.sourceUuid,
        });
        // Note: We do not wait for completion here
        Whisper.Reactions.onReaction(reactionModel);
        confirm();
        return Promise.resolve();
    }

    if (data.message.delete) {
        const { delete: del } = data.message;
        const deleteModel = Whisper.Deletes.add({
        targetSentTimestamp: del.targetSentTimestamp,
        serverTimestamp: data.serverTimestamp,
        fromId: data.source || data.sourceUuid,
        });
        // Note: We do not wait for completion here
        Whisper.Deletes.onDelete(deleteModel);
        confirm();
        return Promise.resolve();
    }

    // Don't wait for handleDataMessage, as it has its own per-conversation queueing
    message.handleDataMessage(data.message, event.confirm);

    return Promise.resolve();
}

async function handleMessageSentProfileUpdate({
  data,
  confirm,
  messageDescriptor,
}) {
  // First set profileSharing = true for the conversation we sent to
  const { id, type } = messageDescriptor;
  const conversation = await ConversationController.getOrCreateAndWait(
    id,
    type
  );

  conversation.set({ profileSharing: true });
  window.Signal.Data.updateConversation(id, conversation.attributes);

  // Then we update our own profileKey if it's different from what we have
  const ourNumber = textsecure.storage.user.getNumber();
  const ourUuid = textsecure.storage.user.getUuid();
  const profileKey = data.message.profileKey.toString('base64');
  const me = await ConversationController.getOrCreate(
    ourNumber || ourUuid,
    'private'
  );

  // Will do the save for us if needed
  await me.setProfileKey(profileKey);

  return confirm();
}

function createSentMessage(data) {
  const now = Date.now();
  let sentTo = [];

  if (data.unidentifiedStatus && data.unidentifiedStatus.length) {
    sentTo = data.unidentifiedStatus.map(item => item.destination);
    const unidentified = _.filter(data.unidentifiedStatus, item =>
      Boolean(item.unidentified)
    );
    // eslint-disable-next-line no-param-reassign
    data.unidentifiedDeliveries = unidentified.map(item => item.destination);
  }

  return new Whisper.Message({
    source: textsecure.storage.user.getNumber(),
    sourceUuid: textsecure.storage.user.getUuid(),
    sourceDevice: data.device,
    sent_at: data.timestamp,
    sent_to: sentTo,
    received_at: now,
    conversationId: data.destination,
    type: 'outgoing',
    sent: true,
    unidentifiedDeliveries: data.unidentifiedDeliveries || [],
    expirationStartTimestamp: Math.min(
      data.expirationStartTimestamp || data.timestamp || Date.now(),
      Date.now()
    ),
  });
}


// Note: We do very little in this function, since everything in handleDataMessage is
//   inside a conversation-specific queue(). Any code here might run before an earlier
//   message is processed in handleDataMessage().
function onSentMessage(event) {
    const { data, confirm } = event;

    const messageDescriptor = getDescriptorForSent(data);

    const { PROFILE_KEY_UPDATE } = textsecure.protobuf.DataMessage.Flags;
    // eslint-disable-next-line no-bitwise
    const isProfileUpdate = Boolean(data.message.flags & PROFILE_KEY_UPDATE);
    if (isProfileUpdate) {
        return handleMessageSentProfileUpdate({
        data,
        confirm,
        messageDescriptor,
        });
    }

    const message = createSentMessage(data);

    const ourNumber = textsecure.storage.user.getNumber();
    const ourUuid = textsecure.storage.user.getUuid();

    if (data.message.reaction) {
        const { reaction } = data.message;
        const reactionModel = Whisper.Reactions.add({
        emoji: reaction.emoji,
        remove: reaction.remove,
        targetAuthorE164: reaction.targetAuthorE164,
        targetAuthorUuid: reaction.targetAuthorUuid,
        targetTimestamp: reaction.targetTimestamp.toNumber(),
        timestamp: Date.now(),
        fromId: ourNumber || ourUuid,
        fromSync: true,
        });
        // Note: We do not wait for completion here
        Whisper.Reactions.onReaction(reactionModel);

        event.confirm();
        return Promise.resolve();
    }

    if (data.message.delete) {
        const { delete: del } = data.message;
        const deleteModel = Whisper.Deletes.add({
        targetSentTimestamp: del.targetSentTimestamp,
        serverTimestamp: del.serverTimestamp,
        fromId: ourNumber || ourUuid,
        });
        // Note: We do not wait for completion here
        Whisper.Deletes.onDelete(deleteModel);
        confirm();
        return Promise.resolve();
    }

    ConversationController.getOrCreate(
        messageDescriptor.id,
        messageDescriptor.type
    );
    // Don't wait for handleDataMessage, as it has its own per-conversation queueing

    message.handleDataMessage(data.message, event.confirm, {
        data,
    });

    return Promise.resolve();
}

function initIncomingMessage(data) {
    const targetId = data.source || data.sourceUuid;
    const conversation = ConversationController.get(targetId);
    const conversationId = conversation ? conversation.id : targetId;

    return new Whisper.Message({
        source: data.source,
        sourceUuid: data.sourceUuid,
        sourceDevice: data.sourceDevice,
        sent_at: data.timestamp,
        serverTimestamp: data.serverTimestamp,
        received_at: Date.now(),
        conversationId,
        unidentifiedDeliveryReceived: data.unidentifiedDeliveryReceived,
        type: 'incoming',
        unread: 1,
    });
}

async function unlinkAndDisconnect() {
  Whisper.events.trigger('unauthorized');

  if (messageReceiver) {
    await messageReceiver.stopProcessing();

    await window.waitForAllBatchers();
    messageReceiver.unregisterBatchers();

    messageReceiver = null;
  }

  window.log.warn(
    'Client is no longer authorized; deleting local configuration'
  );
  window.Signal.Util.Registration.remove();

  const NUMBER_ID_KEY = 'number_id';
  const VERSION_KEY = 'version';
  const LAST_PROCESSED_INDEX_KEY = 'attachmentMigration_lastProcessedIndex';
  const IS_MIGRATION_COMPLETE_KEY = 'attachmentMigration_isComplete';

  const previousNumberId = textsecure.storage.get(NUMBER_ID_KEY);
  const lastProcessedIndex = textsecure.storage.get(LAST_PROCESSED_INDEX_KEY);
  const isMigrationComplete = textsecure.storage.get(
    IS_MIGRATION_COMPLETE_KEY
  );

  try {
    await textsecure.storage.protocol.removeAllConfiguration();

    // These two bits of data are important to ensure that the app loads up
    //   the conversation list, instead of showing just the QR code screen.
    window.Signal.Util.Registration.markEverDone();
    textsecure.storage.put(NUMBER_ID_KEY, previousNumberId);

    // These two are important to ensure we don't rip through every message
    //   in the database attempting to upgrade it after starting up again.
    textsecure.storage.put(
      IS_MIGRATION_COMPLETE_KEY,
      isMigrationComplete || false
    );
    textsecure.storage.put(
      LAST_PROCESSED_INDEX_KEY,
      lastProcessedIndex || null
    );
    textsecure.storage.put(VERSION_KEY, window.getVersion());

    window.log.info('Successfully cleared local configuration');
  } catch (eraseError) {
    window.log.error(
      'Something went wrong clearing local configuration',
      eraseError && eraseError.stack ? eraseError.stack : eraseError
    );
  }
}

function onError(ev) {
    const { error } = ev;
    window.log.error('background onError:', Errors.toLogFormat(error));

    if (
        error &&
        error.name === 'HTTPError' &&
        (error.code === 401 || error.code === 403)
    ) {
        return unlinkAndDisconnect();
    }

    if (
        error &&
        error.name === 'HTTPError' &&
        (error.code === -1 || error.code === 502)
    ) {
        // Failed to connect to server
        if (navigator.onLine) {
        window.log.info('retrying in 1 minute');
        reconnectTimer = setTimeout(connect, 60000);

        Whisper.events.trigger('reconnectTimer');
        }
        return Promise.resolve();
    }

    if (ev.proto) {
        if (error && error.name === 'MessageCounterError') {
        if (ev.confirm) {
            ev.confirm();
        }
        // Ignore this message. It is likely a duplicate delivery
        // because the server lost our ack the first time.
        return Promise.resolve();
        }
        const envelope = ev.proto;
        const message = initIncomingMessage(envelope);

        const conversationId = message.get('conversationId');
        const conversation = ConversationController.getOrCreate(
        conversationId,
        'private'
        );

        // This matches the queueing behavior used in Message.handleDataMessage
        conversation.queueJob(async () => {
        const existingMessage = await window.Signal.Data.getMessageBySender(
            message.attributes,
            {
            Message: Whisper.Message,
            }
        );
        if (existingMessage) {
            ev.confirm();
            window.log.warn(
            `Got duplicate error for message ${message.idForLogging()}`
            );
            return;
        }

        const model = new Whisper.Message({
            ...message.attributes,
            id: window.getGuid(),
        });
        await model.saveErrors(error || new Error('Error was null'), {
            skipSave: true,
        });

        MessageController.register(model.id, model);
        await window.Signal.Data.saveMessage(model.attributes, {
            Message: Whisper.Message,
            forceSave: true,
        });

        conversation.set({
            active_at: Date.now(),
            unreadCount: conversation.get('unreadCount') + 1,
        });

        const conversationTimestamp = conversation.get('timestamp');
        const messageTimestamp = model.get('timestamp');
        if (
            !conversationTimestamp ||
            messageTimestamp > conversationTimestamp
        ) {
            conversation.set({ timestamp: model.get('sent_at') });
        }

        conversation.trigger('newmessage', model);
        conversation.notify(model);

        Whisper.events.trigger('incrementProgress');

        if (ev.confirm) {
            ev.confirm();
        }

        window.Signal.Data.updateConversation(conversation.attributes);
        });
    }

    throw error;
}

//onViewSync

function onReadReceipt(ev) {
  const readAt = ev.timestamp;
  const { timestamp } = ev.read;
  const reader = ConversationController.getConversationId(ev.read.reader);
  window.log.info('read receipt', reader, timestamp);

  ev.confirm();

  if (!storage.get('read-receipt-setting') || !reader) {
    return;
  }

  const receipt = Whisper.ReadReceipts.add({
    reader,
    timestamp,
    read_at: readAt,
  });

  // Note: We do not wait for completion here
  Whisper.ReadReceipts.onReceipt(receipt);
}

function onReadSync(ev) {
  const readAt = ev.timestamp;
  const { timestamp } = ev.read;
  const { sender, senderUuid } = ev.read;
  window.log.info('read sync', sender, senderUuid, timestamp);

  const receipt = Whisper.ReadSyncs.add({
    sender,
    senderUuid,
    timestamp,
    read_at: readAt,
  });

  receipt.on('remove', ev.confirm);

  // Note: Here we wait, because we want read states to be in the database
  //   before we move on.
  return Whisper.ReadSyncs.onReceipt(receipt);
}

async function onVerified(ev) {
    const e164 = ev.verified.destination;
    const uuid = ev.verified.destinationUuid;
    const key = ev.verified.identityKey;
    let state;

    if (ev.confirm) {
        ev.confirm();
    }

    const c = new Whisper.Conversation({
        e164,
        uuid,
        type: 'private',
    });
    const error = c.validate();
    if (error) {
        window.log.error(
        'Invalid verified sync received:',
        e164,
        uuid,
        Errors.toLogFormat(error)
        );
        return;
    }

    switch (ev.verified.state) {
        case textsecure.protobuf.Verified.State.DEFAULT:
        state = 'DEFAULT';
        break;
        case textsecure.protobuf.Verified.State.VERIFIED:
        state = 'VERIFIED';
        break;
        case textsecure.protobuf.Verified.State.UNVERIFIED:
        state = 'UNVERIFIED';
        break;
        default:
        window.log.error(`Got unexpected verified state: ${ev.verified.state}`);
    }

    window.log.info(
        'got verified sync for',
        e164,
        uuid,
        state,
        ev.viaContactSync ? 'via contact sync' : ''
    );

    const contact = await ConversationController.getOrCreateAndWait(
        e164 || uuid,
        'private'
    );
    const options = {
        viaSyncMessage: true,
        viaContactSync: ev.viaContactSync,
        key,
    };

    if (state === 'VERIFIED') {
        await contact.setVerified(options);
    } else if (state === 'DEFAULT') {
        await contact.setVerifiedDefault(options);
    } else {
        await contact.setUnverified(options);
    }
}

function onDeliveryReceipt(ev) {
  const { deliveryReceipt } = ev;
  const { sourceUuid, source } = deliveryReceipt;
  const identifier = source || sourceUuid;

  window.log.info(
    'delivery receipt from',
    `${identifier}.${deliveryReceipt.sourceDevice}`,
    deliveryReceipt.timestamp
  );

  ev.confirm();

  const deliveredTo = ConversationController.getConversationId(identifier);

  if (!deliveredTo) {
    window.log.info('no conversation for identifier', identifier);
    return;
  }

  const receipt = Whisper.DeliveryReceipts.add({
    timestamp: deliveryReceipt.timestamp,
    deliveredTo,
  });

  // Note: We don't wait for completion here
  Whisper.DeliveryReceipts.onReceipt(receipt);
}

//ENDFROM

Whisper.events.on('storage_ready', () => {
  
  if(this.link) {
    return getAccountManager().registerSecondDevice(
      (url) => qrcode.generate(url),
      () => Promise.resolve(this.clientName)
    );
  } else {

    //Redux actions are not needed for our use case but to stop warnings:
    //Adapted from background.js initializeRedux 
    const dummyStore = {};
    window.reduxStore = dummyStore;
    dummyStore.getState = function() { return window.reduxStore; };
    dummyStore.stickers = {};
    dummyStore.stickers.packs = {};
    
    const actions = {};
    window.reduxActions = actions;
    actions.conversations = {};
    actions.emojis = {};
    actions.expiration = {};
    actions.items = {};
    actions.network = {};
    actions.updates = {};
    actions.user = {};
    actions.search = {};
    actions.stickers = {};
    
    //No errors in stickers
    actions.stickers.stickerPackAdded = function() {};
    
    //Needed to be able to send messages:
    actions.conversations.clearUnreadMetrics = function() {};
    actions.conversations.messagesAdded = function() {};
    
    //This is so we can wait for everything as otherwise the async functions end to fast
    //This screws everything up as e.g. the uuid is not loaded before continuing
    (async() => {
      //FROM: background.js
      //Async function connect()
      if (messageReceiver) {
        await messageReceiver.stopProcessing();

        await window.waitForAllBatchers();
        messageReceiver.unregisterBatchers();

        messageReceiver = null;
      }

      const OLD_USERNAME = storage.get('number_id');
      const USERNAME = storage.get('uuid_id');
      const PASSWORD = storage.get('password');
      const mySignalingKey = storage.get('signaling_key');

      connectCount += 1;
      const options = {
        retryCached: connectCount === 1,
        serverTrustRoot: window.getServerTrustRoot(),
      };
      
      //...

      // initialize the socket and start listening for messages
      window.log.info('Initializing socket and listening for messages');
      messageReceiver = new textsecure.MessageReceiver(
        OLD_USERNAME,
        USERNAME,
        PASSWORD,
        mySignalingKey,
        options
      );
      //ENDFROM
      
      // Proxy all the events to the client emitter
      [
        'message',
        'delivery',
        'contact',
        'group',
        'sent',
        'readSync',
        'read',
        'verified',
        'error',
        'configuration',
        'typing',
        'sticker-pack'
      ].forEach((type) => {
        messageReceiver.addEventListener(type, (...args) => {
          this.matrixEmitter.emit(type, ...args);
        });
      });

      this.matrixEmitter.on('message', onMessageReceived);
      this.matrixEmitter.on('delivery', onDeliveryReceipt);
      this.matrixEmitter.on('contact', onContactReceived);
      this.matrixEmitter.on('group', onGroupReceived);
      this.matrixEmitter.on('sent', onSentMessage);
      this.matrixEmitter.on('readSync', onReadSync);
      this.matrixEmitter.on('read', onReadReceipt);
      this.matrixEmitter.on('verified', onVerified);
      this.matrixEmitter.on('error', onError);
      this.matrixEmitter.on('configuration', onConfiguration);
      this.matrixEmitter.on('typing', onTyping);
      this.matrixEmitter.on('sticker-pack', onStickerPack);

      
      //FROM: background.js
      window.textsecure.messaging = new textsecure.MessageSender(
        USERNAME || OLD_USERNAME,
        PASSWORD
      );
      
      //...
      const udSupportKey = 'hasRegisterSupportForUnauthenticatedDelivery';
      if (!storage.get(udSupportKey)) {
        const server = WebAPI.connect({
          username: USERNAME || OLD_USERNAME,
          password: PASSWORD,
        });
        try {
          await server.registerSupportForUnauthenticatedDelivery();
          storage.put(udSupportKey, true);
        } catch (error) {
          window.log.error(
            'Error: Unable to register for unauthenticated delivery support.',
            error && error.stack ? error.stack : error
          );
        }
      }

      const hasRegisteredUuidSupportKey = 'hasRegisteredUuidSupport';
      if (
        !storage.get(hasRegisteredUuidSupportKey) &&
        textsecure.storage.user.getUuid()
      ) {
        const server = WebAPI.connect({
          username: USERNAME || OLD_USERNAME,
          password: PASSWORD,
        });
        try {
          await server.registerCapabilities({ uuid: true });
          storage.put(hasRegisteredUuidSupportKey, true);
        } catch (error) {
          window.log.error(
            'Error: Unable to register support for UUID messages.',
            error && error.stack ? error.stack : error
          );
        }
      }

      const deviceId = textsecure.storage.user.getDeviceId();

      if (!textsecure.storage.user.getUuid()) {
        const server = WebAPI.connect({
          username: OLD_USERNAME,
          password: PASSWORD,
        });
        try {
          const { uuid } = await server.whoami();
          textsecure.storage.user.setUuidAndDeviceId(uuid, deviceId);
          const ourNumber = textsecure.storage.user.getNumber();
          const me = await ConversationController.getOrCreateAndWait(
            ourNumber,
            'private'
          );
          me.updateUuid(uuid);
        } catch (error) {
          window.log.error(
            'Error: Unable to retrieve UUID from service.',
            error && error.stack ? error.stack : error
          );
        }
      }
      
      //ENDFROM
      
      Whisper.RotateSignedPreKeyListener.init(Whisper.events);
      window.Signal.RefreshSenderCertificate.initialize({
        events: Whisper.events,
        storage,
        navigator,
        logger: window.log,
      });
      Whisper.ExpiringMessagesListener.init(Whisper.events);
      
      Whisper.deliveryReceiptQueue.start();
      this.matrixEmitter.emit( 'client_ready' );
      
    })();

    return Promise.resolve(this.matrixEmitter);
  }
});

async function getStorageReady() {
  let key = keyStore.get('key');
  //FROM: main.js
  if (!key) {
    console.log(
      'key/initialize: Generating new encryption key, since we did not find it on disk'
    );
    // https://www.zetetic.net/sqlcipher/sqlcipher-api/#key
    key = crypto.randomBytes(32).toString('hex');
    keyStore.put('key', key);
  }

  //Adapted
  const sqlInitPromise = sql.initialize({
    configDir: process.cwd() + '/data/',
    key,
    messages: {},
  });
  const success = await sqlInitPromise;

  if (!success) {
    console.log('sql.initialize was unsuccessful; returning early');
    return;
  }
  await sqlChannels.initialize();
//ENDFROM
  
  window.document = {};
  
  window.log.info('Storage fetch');
  await storage.fetch();
  try {
    await Promise.all([
      ConversationController.load(),
      textsecure.storage.protocol.hydrateCaches(),
    ]);
  } catch (error) {
    window.log.error(
      'background.js: ConversationController failed to load:',
      error && error.stack ? error.stack : error
    );
  } finally {
    console.log('triggering storage ready');
    Whisper.events.trigger('storage_ready');
  }
}

const startSequence = (clientName, matrixEmitter) => {

  this.clientName = clientName;
  this.link = false;
  this.matrixEmitter = matrixEmitter;
  getStorageReady();

  const link = () => {
    this.link = true;
    return null;
  }

  const init = () => {
    return null;
  }

  return {
    link,
    init
  };
}

const EventEmitter = require('events').EventEmitter;

class SignalClient extends EventEmitter {
  constructor(clientName = "nodejs") {
    super();
    this.clientName = clientName;
  }

  start() {
    if (messageReceiver)
      return Promise.resolve(this);

    return startSequence(this.clientName, this).init();
  }

  link() {
    return startSequence(this.clientName, this).link();
  }

  syncGroups() {
    return textsecure.messaging.sendRequestGroupSyncMessage();
  }

  syncContacts() {
    return textsecure.messaging.sendRequestContactSyncMessage(); 
  }
  
  async getProfileNameForId(conversationId) {
    const conversation = await ConversationController.getOrCreateAndWait(conversationId, 'private');
    return conversation.getProfileName();
  }

  async downloadAttachment(attachment) {
    return messageReceiver.downloadAttachment(attachment);
  }
  
  async getPathForAvatar(conversationId, isGroup) {
    let conversation;
    if (isGroup) {
      conversation = await ConversationController.getOrCreateAndWait(conversationId, 'group');
    }
    else { 
      conversation = await ConversationController.getOrCreateAndWait(conversationId, 'private');
    }
    
    return await conversation.getAvatarPath();
  }
    
  async leaveGroup(conversationId) {
    let conversation = await ConversationController.getOrCreateAndWait(conversationId, 'group');
    conversation.leaveGroup();
  }
    
  /**
   * mark messages as read in your signal clients
   */
  async syncReadReceipts(conversationId, isGroup, timeStamp, sendReceipts = true) {
    storage.put('read-receipt-setting', sendReceipts);
    if (sendReceipts) {
      let conversation;
      if (isGroup) {
        conversation = await ConversationController.getOrCreateAndWait(conversationId, 'group');
      }
      else { 
        conversation = await ConversationController.getOrCreateAndWait(conversationId, 'private');
      }
      
      await conversation.markRead(timeStamp, {sendReadReceipts: sendReceipts, readAt: timeStamp });
    }
  }

    /**
   * send typing events to your contacts
   */
  async sendTypingMessage(conversationId, isGroup, status, sendTyping = true) {
    storage.put('typingIndicators', sendTyping);
    window.log.info(sendTyping);
    if (sendTyping) {
      let conversation;
      if (isGroup) {
        conversation = await ConversationController.getOrCreateAndWait(conversationId, 'group');
      }
      else { 
        conversation = await ConversationController.getOrCreateAndWait(conversationId, 'private');
      }
      
      await conversation.sendTypingMessage(status);
    }
  }

    /**
     * Sends a reaction message
     * @param {object} reaction - The reaction to send
     * @param {string} reaction.emoji - The emoji to react with
     * @param {boolean} [reaction.remove] - Set to `true` if we are removing a
     *   reaction with the given emoji
     * @param {object} target - The target of the reaction
     * @param {string} [target.targetAuthorE164] - The E164 address of the target
     *   message's author
     * @param {string} [target.targetAuthorUuid] - The UUID address of the target
     *   message's author
     * @param {number} target.targetTimestamp - The sent_at timestamp of the
     *   target message
     */
  async sendReactionMessage(conversationId, isGroup, reaction, target) {
    let conversation;
    if (isGroup) {
      conversation = await ConversationController.getOrCreateAndWait(conversationId, 'group');      
    }
    else {
      conversation = await ConversationController.getOrCreateAndWait(conversationId, 'private');
    }
    await conversation.sendReactionMessage(reaction, target);
  }

  async sendMessage(conversationId, isGroup, body, finalizedAttachments = [], quote = null) {
    
    let preview = [];
    let sticker = null;
    //We start without attachments to prevent errors from spawning from not having electron running
    let attachments = []
    
    let conversation;
    if (isGroup) {
      conversation = await ConversationController.getOrCreateAndWait(conversationId, 'group');      
    }
    else {
      conversation = await ConversationController.getOrCreateAndWait(conversationId, 'private');
    }
    
    //FROM: conversation.js
    //This is just conversation.sendMessage() with two things changed:
    //the date is moved outside the queue job (we need it for read receipts)
    //this. changed to conversation. 

    conversation.clearTypingTimers();

    const { clearUnreadMetrics } = window.reduxActions.conversations;
    clearUnreadMetrics(conversation.id);

    const destination = conversation.get('uuid') || conversation.get('e164');
    const expireTimer = conversation.get('expireTimer');
    const recipients = conversation.getRecipients();

    let profileKey;
    if (conversation.get('profileSharing')) {
      profileKey = storage.get('profileKey');
    }
    
    //Moved outside so we can use it for read receipts later
    const now = Date.now();

    conversation.queueJob(async () => {

      window.log.info(
        'Sending message to conversation',
        conversation.idForLogging(),
        'with timestamp',
        now
      );

      // Here we move attachments to disk
      const messageWithSchema = await upgradeMessageSchema({
        type: 'outgoing',
        body,
        conversationId: conversation.id,
        quote,
        preview,
        attachments,
        sent_at: now,
        received_at: now,
        expireTimer,
        recipients,
        sticker,
      });
      
      if (conversation.isPrivate()) {
        messageWithSchema.destination = destination;
      }
      const attributes = {
        ...messageWithSchema,
        id: window.getGuid(),
      };

      const model = conversation.addSingleMessage(attributes);
      if (sticker) {
        await addStickerPackReference(model.id, sticker.packId);
      }
      const message = MessageController.register(model.id, model);
      await window.Signal.Data.saveMessage(message.attributes, {
        forceSave: true,
        Message: Whisper.Message,
      });

      conversation.set({
        lastMessage: model.getNotificationText(),
        lastMessageStatus: 'sending',
        active_at: now,
        timestamp: now,
        isArchived: false,
        draft: null,
        draftTimestamp: null,
      });
      window.Signal.Data.updateConversation(conversation.id, conversation.attributes);

      // We're offline!
      if (!textsecure.messaging) {
        const errors = (conversation.contactCollection.length
          ? conversation.contactCollection
          : [this]
        ).map(contact => {
          const error = new Error('Network is not available');
          error.name = 'SendMessageNetworkError';
          error.identifier = contact.get('uuid') || contact.get('e164');
          return error;
        });
        await message.saveErrors(errors);
        return null;
      }

      const attachmentsWithData = await Promise.all(
        messageWithSchema.attachments.map(loadAttachmentData)
      );

      //Adapted to replace finalAttachments by our attachments
      let {
        body: messageBody,
        attachments: finalAttachments,
      } = Whisper.Message.getLongMessageAttachment({
        body,
        attachments: attachmentsWithData,
        now,
      });
      finalAttachments = finalizedAttachments;

      // Special-case the self-send case - we send only a sync message
      if (conversation.isMe()) {
        const dataMessage = await textsecure.messaging.getMessageProto(
          destination,
          messageBody,
          finalAttachments,
          quote,
          preview,
          sticker,
          null,
          now,
          expireTimer,
          profileKey
        );
        return message.sendSyncMessageOnly(dataMessage);
      }

      const conversationType = conversation.get('type');
      const options = conversation.getSendOptions();
      
      const promise = (() => {
        switch (conversationType) {
          case Message.PRIVATE:
            return textsecure.messaging.sendMessageToIdentifier(
              destination,
              messageBody,
              finalAttachments,
              quote,
              preview,
              sticker,
              null,
              now,
              expireTimer,
              profileKey,
              options
            );
          case Message.GROUP:
            return textsecure.messaging.sendMessageToGroup(
              conversation.get('groupId'),
              conversation.getRecipients(),
              messageBody,
              finalAttachments,
              quote,
              preview,
              sticker,
              null,
              now,
              expireTimer,
              profileKey,
              options
            );
          default:
            throw new TypeError(
              `Invalid conversation type: '${conversationType}'`
            );
        }
      })();

      return message.send(conversation.wrapSend(promise));
    });
    
    //ENDFROM
    
    let members = [];
    let conversationIndividual;
    
    if (isGroup) {
      for (let i=0; i < recipients.length; ++i) {
        conversationIndividual = await ConversationController.getOrCreateAndWait(recipients[i], 'group');
        members.push(conversationIndividual.get('e164'));
      }
    }
    else {
      members.push(conversation.get('e164'));
    }
    
    return {timeStamp: now, members};
  }
}

module.exports = SignalClient;
