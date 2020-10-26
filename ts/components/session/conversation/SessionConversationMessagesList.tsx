import React from 'react';

import { Message } from '../../conversation/Message';
import { TimerNotification } from '../../conversation/TimerNotification';

import { SessionScrollButton } from '../SessionScrollButton';
import { ResetSessionNotification } from '../../conversation/ResetSessionNotification';
import { Constants } from '../../../session';
import _ from 'lodash';
import { ConversationModel } from '../../../../js/models/conversations';
import { contextMenu } from 'react-contexify';
import { AttachmentType } from '../../../types/Attachment';

interface State {
  isScrolledToBottom: boolean;
  showScrollButton: boolean;
  doneInitialScroll: boolean;
}

interface Props {
  selectedMessages: Array<string>;
  conversationKey: string;
  messages: Array<any>;
  resetSelection: () => any;
  initialFetchComplete: boolean;
  conversationModel: ConversationModel;
  conversation: any;
  messageContainerRef: React.RefObject<any>;
  selectMessage: (messageId: string) => void;
  getMessages: (
    numMessages: number,
    interval: number
  ) => Promise<{ previousTopMessage: string }>;
  replyToMessage: (messageId: number) => Promise<void>;
  onClickAttachment: (attachment: any, message: any) => void;
  onDownloadAttachment: ({ attachment }: { attachment: any}) => void;
}

export class SessionConversationMessagesList extends React.Component<
  Props,
  State
> {
  private readonly messagesEndRef: React.RefObject<HTMLDivElement>;
  private readonly messageContainerRef: React.RefObject<any>;

  public constructor(props: Props) {
    super(props);

    this.state = {
      isScrolledToBottom: false,
      showScrollButton: true,
      doneInitialScroll: false,
    };
    this.renderMessage = this.renderMessage.bind(this);
    this.handleScroll = this.handleScroll.bind(this);
    this.scrollToUnread = this.scrollToUnread.bind(this);
    this.scrollToBottom = this.scrollToBottom.bind(this);

    this.messagesEndRef = React.createRef();
    this.messageContainerRef = this.props.messageContainerRef;
  }

  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // ~~~~~~~~~~~~~~~~ LIFECYCLES ~~~~~~~~~~~~~~~~
  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  public componentDidMount() {
    // Pause thread to wait for rendering to complete
    setTimeout(this.scrollToUnread, 0);
    setTimeout(() => {
      this.setState({
        doneInitialScroll: true,
      });
    }, 100);

    this.updateReadMessages();
  }

  public componentDidUpdate() {
    // Keep scrolled to bottom unless user scrolls up
    if (this.state.isScrolledToBottom) {
      this.scrollToBottom();
      this.updateReadMessages();
    }

    // New messages get from message collection.
    const messageCollection = window.ConversationController.get(
      this.props.conversationKey
    )?.messageCollection;
  }

  public async componentWillReceiveProps(nextProps: any) {
    return;
  }

  public render() {
    const { messages } = this.props;

    const { doneInitialScroll, showScrollButton } = this.state;

    if (!doneInitialScroll) {
      return <div className="messages-container__loading" />;
    }
    return (
      <div
        className="messages-container"
        onScroll={this.handleScroll}
        ref={this.messageContainerRef}
      >
        {this.renderMessages(messages)}
        <div ref={this.messagesEndRef} />

        <SessionScrollButton
          show={showScrollButton}
          onClick={this.scrollToBottom}
        />
      </div>
    );
  }

  public renderMessages(messages: any) {
    const multiSelectMode = Boolean(this.props.selectedMessages.length);
    // FIXME VINCE: IF MESSAGE IS THE TOP OF UNREAD, THEN INSERT AN UNREAD BANNER
    return (
      <>
        {messages.map((message: any) => {
          const messageProps = message.propsForMessage;

          const timerProps = message.propsForTimerNotification;
          const resetSessionProps = message.propsForResetSessionNotification;

          const attachmentProps = message.propsForAttachment;
          const groupNotificationProps = message.propsForGroupNotification;

          let item;
          // firstMessageOfSeries tells us to render the avatar only for the first message
          // in a series of messages from the same user
          item = messageProps
            ? this.renderMessage(
                messageProps,
                message.firstMessageOfSeries,
                multiSelectMode
              )
            : item;

          item = timerProps ? <TimerNotification {...timerProps} /> : item;
          item = resetSessionProps ? (
            <ResetSessionNotification {...resetSessionProps} />
          ) : (
            item
          );

          return item;
        })}
      </>
    );
  }

  public renderMessage(
    messageProps: any,
    firstMessageOfSeries: boolean,
    multiSelectMode: boolean
  ) {
    const selected =
      !!messageProps?.id &&
      this.props.selectedMessages.includes(messageProps.id);

    messageProps.i18n = window.i18n;
    messageProps.selected = selected;
    messageProps.firstMessageOfSeries = firstMessageOfSeries;
    messageProps.multiSelectMode = multiSelectMode;
    messageProps.onSelectMessage = (messageId: string) => {
      this.selectMessage(messageId);
    };

    messageProps.onReply = (messageId: number) => {
      void this.props.replyToMessage(messageId);
    };

    messageProps.onClickAttachment = (attachment: any) => {
      this.props.onClickAttachment(attachment, messageProps);
    };
    messageProps.onDownload = (attachment: AttachmentType) => {
      this.props.onDownloadAttachment({attachment});
    };

    return <Message {...messageProps} />;
  }

  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // ~~~~~~~~~~~~~ MESSAGE HANDLING ~~~~~~~~~~~~~
  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  public updateReadMessages() {
    const { messages, conversationKey } = this.props;
    const { isScrolledToBottom } = this.state;

    // If you're not friends, don't mark anything as read. Otherwise
    // this will automatically accept friend request.
    const conversation = window.ConversationController.getOrThrow(
      conversationKey
    );

    if (conversation.isBlocked()) {
      return;
    }

    let unread;

    if (!messages || messages.length === 0) {
      return;
    }

    if (isScrolledToBottom) {
      unread = messages[messages.length - 1];
    } else {
      unread = this.findNewestVisibleUnread();
    }

    if (unread) {
      conversation.markRead(unread.attributes.received_at);
    }
  }

  public findNewestVisibleUnread() {
    const messageContainer = this.messageContainerRef.current;
    if (!messageContainer) {
      return null;
    }

    const { messages, conversation } = this.props;
    const { length } = messages;

    const viewportBottom =
      (messageContainer?.clientHeight as number) +
        (messageContainer?.scrollTop as number) || 0;

    // Start with the most recent message, search backwards in time
    let foundUnread = 0;
    for (let i = length - 1; i >= 0; i -= 1) {
      // Search the latest 30, then stop if we believe we've covered all known
      //   unread messages. The unread should be relatively recent.
      // Why? local notifications can be unread but won't be reflected the
      //   conversation's unread count.
      if (i > 30 && foundUnread >= conversation.unreadCount) {
        return null;
      }

      const message = messages[i];

      if (!message.attributes.unread) {
        // eslint-disable-next-line no-continue
        continue;
      }

      foundUnread += 1;

      const el = document.getElementById(`${message.id}`);

      if (!el) {
        // eslint-disable-next-line no-continue
        continue;
      }

      const top = el.offsetTop;

      // If the bottom fits on screen, we'll call it visible. Even if the
      //   message is really tall.
      const height = el.offsetHeight;
      const bottom = top + height;

      // We're fully below the viewport, continue searching up.
      if (top > viewportBottom) {
        // eslint-disable-next-line no-continue
        continue;
      }

      if (bottom <= viewportBottom) {
        return message;
      }

      // Continue searching up.
    }

    return null;
  }

  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // ~~~~~~~~~~~~ SCROLLING METHODS ~~~~~~~~~~~~~
  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  public async handleScroll() {
    const messageContainer = this.messageContainerRef?.current;
    if (!messageContainer) {
      return;
    }
    contextMenu.hideAll();

    const scrollTop = messageContainer.scrollTop;
    const scrollHeight = messageContainer.scrollHeight;
    const clientHeight = messageContainer.clientHeight;

    const scrollButtonViewShowLimit = 0.75;
    const scrollButtonViewHideLimit = 0.4;
    const scrollOffsetPx = scrollHeight - scrollTop - clientHeight;
    const scrollOffsetPc = scrollOffsetPx / clientHeight;

    // Scroll button appears if you're more than 75% scrolled up
    if (
      scrollOffsetPc > scrollButtonViewShowLimit &&
      !this.state.showScrollButton
    ) {
      this.setState({ showScrollButton: true });
    }
    // Scroll button disappears if you're more less than 40% scrolled up
    if (
      scrollOffsetPc < scrollButtonViewHideLimit &&
      this.state.showScrollButton
    ) {
      this.setState({ showScrollButton: false });
    }

    // Scrolled to bottom
    const isScrolledToBottom = scrollOffsetPc === 0;

    // Mark messages read
    this.updateReadMessages();

    // Pin scroll to bottom on new message, unless user has scrolled up
    if (this.state.isScrolledToBottom !== isScrolledToBottom) {
      this.setState({ isScrolledToBottom });
    }

    // Fetch more messages when nearing the top of the message list
    const shouldFetchMoreMessages =
      scrollTop <= Constants.UI.MESSAGE_CONTAINER_BUFFER_OFFSET_PX;

    if (shouldFetchMoreMessages) {
      const numMessages =
        this.props.messages.length +
        Constants.CONVERSATION.DEFAULT_MESSAGE_FETCH_COUNT;

      // Prevent grabbing messags with scroll more frequently than once per 2s.
      const messageFetchInterval = 2;
      const previousTopMessage = (
        await this.props.getMessages(numMessages, messageFetchInterval)
      )?.previousTopMessage;

      if (previousTopMessage) {
        this.scrollToMessage(previousTopMessage);
      }
    }
  }

  public scrollToUnread() {
    const { messages, conversation } = this.props;
    const message = messages[messages.length - 1 - conversation.unreadCount];

    if (message) {
      this.scrollToMessage(message.id);
    }
  }

  public scrollToMessage(messageId: string) {
    const topUnreadMessage = document.getElementById(messageId);
    topUnreadMessage?.scrollIntoView();
  }

  public scrollToBottom() {
    // FIXME VINCE: Smooth scrolling that isn't slow@!
    // this.messagesEndRef.current?.scrollIntoView(
    //   { behavior: firstLoad ? 'auto' : 'smooth' }
    // );

    const messageContainer = this.messageContainerRef.current;
    if (!messageContainer) {
      return;
    }
    messageContainer.scrollTop =
      messageContainer.scrollHeight - messageContainer.clientHeight;
  }

  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // ~~~~~~~~~~~~ MESSAGE SELECTION ~~~~~~~~~~~~~
  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  public selectMessage(messageId: string) {
    this.props.selectMessage(messageId);
  }

  public resetSelection() {
    this.props.resetSelection();
  }

  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  // ~~~~~~~~~~~ KEYBOARD NAVIGATION ~~~~~~~~~~~~
  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  private onKeyDown(event: any) {
    //FIXME Audric
    //   const messageContainer = this.messageContainerRef.current;
    //   if (!messageContainer) {
    //     return;
    //   }
    //   const selectionMode = !!this.props.selectedMessages.length;
    //   const recordingMode = this.props.showRecordingView;
    //   const pageHeight = messageContainer.clientHeight;
    //   const arrowScrollPx = 50;
    //   const pageScrollPx = pageHeight * 0.8;
    //   if (event.key === 'Escape') {
    //     // EXIT MEDIA VIEW
    //     if (recordingMode) {
    //       // EXIT RECORDING VIEW
    //     }
    //     // EXIT WHAT ELSE?
    //   }
    //   switch (event.key) {
    //     case 'Escape':
    //       if (selectionMode) {
    //         this.resetSelection();
    //       }
    //       break;
    //     // Scrolling
    //     case 'ArrowUp':
    //       messageContainer.scrollBy(0, -arrowScrollPx);
    //       break;
    //     case 'ArrowDown':
    //       messageContainer.scrollBy(0, arrowScrollPx);
    //       break;
    //     case 'PageUp':
    //       messageContainer.scrollBy(0, -pageScrollPx);
    //       break;
    //     case 'PageDown':
    //       messageContainer.scrollBy(0, pageScrollPx);
    //       break;
    //     default:
    //   }
  }
}
