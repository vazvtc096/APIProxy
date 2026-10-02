package com.apiproxy.service;

import com.apiproxy.entity.*;
import com.apiproxy.repository.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * 社交服务。
 *
 * 对应 Python social.py + routes/social.py。
 * Post: postId / userUid / userName / title / content / status / likes(Integer)；
 * PostFavorite: userUid / postId(String)；
 * PostCollection: uid / postId(Integer)；
 * Friend: userUid / friendUid / friendName / status / acceptedAt；
 * ChatMessage: fromUid / fromName / toUid / toName / content / isRead(Integer)；
 * User: userName / balence(Double) / uid。
 */
@Service
public class SocialService {

    private static final Logger log = LoggerFactory.getLogger(SocialService.class);

    private final PostRepository postRepository;
    private final PostFavoriteRepository postFavoriteRepository;
    private final PostCollectionRepository postCollectionRepository;
    private final FriendRepository friendRepository;
    private final ChatMessageRepository chatMessageRepository;
    private final UserRepository userRepository;
    private final BalenceTransactionRepository balenceTransactionRepository;

    public SocialService(PostRepository postRepository,
                         PostFavoriteRepository postFavoriteRepository,
                         PostCollectionRepository postCollectionRepository,
                         FriendRepository friendRepository,
                         ChatMessageRepository chatMessageRepository,
                         UserRepository userRepository,
                         BalenceTransactionRepository balenceTransactionRepository) {
        this.postRepository = postRepository;
        this.postFavoriteRepository = postFavoriteRepository;
        this.postCollectionRepository = postCollectionRepository;
        this.friendRepository = friendRepository;
        this.chatMessageRepository = chatMessageRepository;
        this.userRepository = userRepository;
        this.balenceTransactionRepository = balenceTransactionRepository;
    }

    // ---------- 帖子 ----------

    @Transactional
    public Post createPost(String username, String title, String content, String category) {
        User user = userRepository.findByUserName(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        Post post = new Post();
        post.setPostId("POST" + System.currentTimeMillis());
        post.setUserUid(user.getUid());
        post.setUserName(username);
        post.setTitle(title);
        post.setContent(content);
        post.setStatus("published");
        post.setLikes(0);
        post.setCreatedAt(LocalDateTime.now());
        return postRepository.save(post);
    }

    public Page<Post> listPosts(int page, int size, String category, String username) {
        PageRequest pr = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
        if (username != null && !username.isBlank()) {
            List<Post> all = postRepository.findAll();
            List<Post> filtered = all.stream()
                    .filter(p -> username.equals(p.getUserName()))
                    .toList();
            return paginate(filtered, pr);
        }
        // 默认只返回已发布的帖子
        List<Post> published = postRepository.findByStatusOrderByCreatedAtDesc("published");
        return paginate(published, pr);
    }

    public Post getPost(Integer id) {
        Post post = postRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Post not found"));
        return post;
    }

    @Transactional
    public void deletePost(Integer id, String username) {
        Post post = postRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Post not found"));
        if (!username.equals(post.getUserName())) {
            throw new SecurityException("Not authorized to delete this post");
        }
        postRepository.delete(post);
    }

    @Transactional
    public void toggleLike(Integer postId, String username) {
        Post post = postRepository.findById(postId)
                .orElseThrow(() -> new IllegalArgumentException("Post not found"));
        User user = userRepository.findByUserName(username).orElse(null);
        String userUid = user != null ? user.getUid() : username;
        String postIdStr = String.valueOf(postId);
        boolean exists = postFavoriteRepository.findAll().stream()
                .anyMatch(f -> userUid.equals(f.getUserUid()) && postIdStr.equals(f.getPostId()));
        if (exists) {
            postFavoriteRepository.findAll().stream()
                    .filter(f -> userUid.equals(f.getUserUid()) && postIdStr.equals(f.getPostId()))
                    .findFirst()
                    .ifPresent(postFavoriteRepository::delete);
            post.setLikes(Math.max(0, (post.getLikes() != null ? post.getLikes() : 0) - 1));
        } else {
            PostFavorite fav = new PostFavorite();
            fav.setUserUid(userUid);
            fav.setPostId(postIdStr);
            fav.setCreatedAt(LocalDateTime.now());
            postFavoriteRepository.save(fav);
            post.setLikes((post.getLikes() != null ? post.getLikes() : 0) + 1);
        }
        postRepository.save(post);
    }

    @Transactional
    public void toggleCollection(Integer postId, String username) {
        User user = userRepository.findByUserName(username).orElse(null);
        String uid = user != null ? user.getUid() : username;
        boolean exists = postCollectionRepository.findAll().stream()
                .anyMatch(c -> uid.equals(c.getUid()) && postId.equals(c.getPostId()));
        if (exists) {
            postCollectionRepository.findAll().stream()
                    .filter(c -> uid.equals(c.getUid()) && postId.equals(c.getPostId()))
                    .findFirst()
                    .ifPresent(postCollectionRepository::delete);
        } else {
            PostCollection col = new PostCollection();
            col.setUid(uid);
            col.setPostId(postId);
            col.setCreatedAt(LocalDateTime.now());
            postCollectionRepository.save(col);
        }
    }

    public List<Post> getUserCollections(String username) {
        User user = userRepository.findByUserName(username).orElse(null);
        String uid = user != null ? user.getUid() : username;
        List<Integer> postIds = postCollectionRepository.findAll().stream()
                .filter(c -> uid.equals(c.getUid()))
                .map(PostCollection::getPostId)
                .toList();
        return postRepository.findAllById(postIds);
    }

    // ---------- 好友系统 ----------

    @Transactional
    public void sendFriendRequest(String fromUsername, String toUsername) {
        if (fromUsername.equals(toUsername)) {
            throw new IllegalArgumentException("Cannot add yourself as friend");
        }
        User toUser = userRepository.findByUserName(toUsername)
                .orElseThrow(() -> new IllegalArgumentException("Target user not found"));
        User fromUser = userRepository.findByUserName(fromUsername)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        // 检查是否已是好友
        boolean alreadyFriend = friendRepository.findAll().stream()
                .anyMatch(f -> fromUser.getUid().equals(f.getUserUid())
                        && toUser.getUid().equals(f.getFriendUid())
                        && "accepted".equals(f.getStatus()));
        if (alreadyFriend) {
            throw new IllegalStateException("Already friends");
        }
        // 检查对方是否已向我发送请求
        boolean reversePending = friendRepository.findAll().stream()
                .anyMatch(f -> toUser.getUid().equals(f.getUserUid())
                        && fromUser.getUid().equals(f.getFriendUid())
                        && "pending".equals(f.getStatus()));
        if (reversePending) {
            acceptFriendRequest(toUsername, fromUsername);
            return;
        }
        Friend friend = new Friend();
        friend.setUserUid(fromUser.getUid());
        friend.setFriendUid(toUser.getUid());
        friend.setFriendName(toUsername);
        friend.setStatus("pending");
        friend.setCreatedAt(LocalDateTime.now());
        friendRepository.save(friend);
        log.info("Friend request: {} -> {}", fromUsername, toUsername);
    }

    @Transactional
    public void acceptFriendRequest(String fromUsername, String toUsername) {
        User fromUser = userRepository.findByUserName(fromUsername)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        User toUser = userRepository.findByUserName(toUsername)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        Friend request = friendRepository.findAll().stream()
                .filter(f -> fromUser.getUid().equals(f.getUserUid())
                        && toUser.getUid().equals(f.getFriendUid())
                        && "pending".equals(f.getStatus()))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Friend request not found"));
        request.setStatus("accepted");
        request.setAcceptedAt(LocalDateTime.now());
        friendRepository.save(request);
        // 创建反向好友关系
        Friend reverse = new Friend();
        reverse.setUserUid(toUser.getUid());
        reverse.setFriendUid(fromUser.getUid());
        reverse.setFriendName(fromUsername);
        reverse.setStatus("accepted");
        reverse.setCreatedAt(LocalDateTime.now());
        reverse.setAcceptedAt(LocalDateTime.now());
        friendRepository.save(reverse);
        log.info("Friend request accepted: {} <-> {}", fromUsername, toUsername);
    }

    @Transactional
    public void rejectFriendRequest(String fromUsername, String toUsername) {
        User fromUser = userRepository.findByUserName(fromUsername)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        User toUser = userRepository.findByUserName(toUsername)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        Friend request = friendRepository.findAll().stream()
                .filter(f -> fromUser.getUid().equals(f.getUserUid())
                        && toUser.getUid().equals(f.getFriendUid())
                        && "pending".equals(f.getStatus()))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Friend request not found"));
        request.setStatus("rejected");
        friendRepository.save(request);
    }

    public List<Friend> getFriends(String username) {
        User user = userRepository.findByUserName(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        return friendRepository.findByUserUidAndStatus(user.getUid(), "accepted");
    }

    public List<Friend> getFriendRequests(String username) {
        User user = userRepository.findByUserName(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        return friendRepository.findAll().stream()
                .filter(f -> user.getUid().equals(f.getFriendUid()) && "pending".equals(f.getStatus()))
                .toList();
    }

    @Transactional
    public void removeFriend(String username, String friendUsername) {
        User user = userRepository.findByUserName(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        User friend = userRepository.findByUserName(friendUsername)
                .orElseThrow(() -> new IllegalArgumentException("Friend not found"));
        friendRepository.findAll().stream()
                .filter(f -> (user.getUid().equals(f.getUserUid()) && friend.getUid().equals(f.getFriendUid()))
                        || (friend.getUid().equals(f.getUserUid()) && user.getUid().equals(f.getFriendUid())))
                .forEach(friendRepository::delete);
    }

    // ---------- 私信 ----------

    @Transactional
    public ChatMessage sendMessage(String fromUsername, String toUsername, String content) {
        User fromUser = userRepository.findByUserName(fromUsername)
                .orElseThrow(() -> new IllegalArgumentException("Sender not found"));
        User toUser = userRepository.findByUserName(toUsername)
                .orElseThrow(() -> new IllegalArgumentException("Recipient not found"));
        boolean isFriend = friendRepository.findAll().stream()
                .anyMatch(f -> fromUser.getUid().equals(f.getUserUid())
                        && toUser.getUid().equals(f.getFriendUid())
                        && "accepted".equals(f.getStatus()));
        if (!isFriend) {
            throw new SecurityException("Can only message friends");
        }
        ChatMessage msg = new ChatMessage();
        msg.setMessageId("MSG" + System.currentTimeMillis());
        msg.setFromUid(fromUser.getUid());
        msg.setFromName(fromUsername);
        msg.setToUid(toUser.getUid());
        msg.setToName(toUsername);
        msg.setContent(content);
        msg.setType("text");
        msg.setStatus("sent");
        msg.setIsRead(0);
        msg.setCreatedAt(LocalDateTime.now());
        return chatMessageRepository.save(msg);
    }

    public List<ChatMessage> getConversation(String username1, String username2, int limit) {
        User u1 = userRepository.findByUserName(username1).orElse(null);
        User u2 = userRepository.findByUserName(username2).orElse(null);
        if (u1 == null || u2 == null) return List.of();
        return chatMessageRepository.findAll().stream()
                .filter(m -> (u1.getUid().equals(m.getFromUid()) && u2.getUid().equals(m.getToUid()))
                        || (u2.getUid().equals(m.getFromUid()) && u1.getUid().equals(m.getToUid())))
                .sorted((a, b) -> b.getCreatedAt().compareTo(a.getCreatedAt()))
                .limit(limit)
                .toList();
    }

    @Transactional
    public void markAsRead(String fromUsername, String toUsername) {
        User from = userRepository.findByUserName(fromUsername).orElse(null);
        User to = userRepository.findByUserName(toUsername).orElse(null);
        if (from == null || to == null) return;
        chatMessageRepository.findAll().stream()
                .filter(m -> from.getUid().equals(m.getFromUid())
                        && to.getUid().equals(m.getToUid())
                        && m.getIsRead() != null && m.getIsRead() == 0)
                .forEach(m -> {
                    m.setIsRead(1);
                    m.setReadAt(LocalDateTime.now());
                    chatMessageRepository.save(m);
                });
    }

    // ---------- 转账 ----------

    @Transactional
    public Map<String, Object> transferBalance(String fromUsername, String toUsername, double amount, String note) {
        if (amount <= 0) {
            throw new IllegalArgumentException("Invalid amount");
        }
        User fromUser = userRepository.findByUserName(fromUsername)
                .orElseThrow(() -> new IllegalArgumentException("Sender not found"));
        User toUser = userRepository.findByUserName(toUsername)
                .orElseThrow(() -> new IllegalArgumentException("Recipient not found"));
        boolean isFriend = friendRepository.findAll().stream()
                .anyMatch(f -> fromUser.getUid().equals(f.getUserUid())
                        && toUser.getUid().equals(f.getFriendUid())
                        && "accepted".equals(f.getStatus()));
        if (!isFriend) {
            throw new SecurityException("Can only transfer to friends");
        }
        double fromBalance = fromUser.getBalence() != null ? fromUser.getBalence() : 0.0;
        if (fromBalance < amount) {
            throw new IllegalStateException("Insufficient balance");
        }
        double toBalance = toUser.getBalence() != null ? toUser.getBalence() : 0.0;

        fromUser.setBalence(fromBalance - amount);
        toUser.setBalence(toBalance + amount);
        userRepository.save(fromUser);
        userRepository.save(toUser);

        String txId = "TX" + System.currentTimeMillis();
        // 扣款记录
        BalenceTransaction debit = new BalenceTransaction();
        debit.setTransactionId(txId);
        debit.setUserUid(fromUser.getUid());
        debit.setUserName(fromUsername);
        debit.setType("transfer_out");
        debit.setAmount(-amount);
        debit.setBalenceAfter(fromUser.getBalence());
        debit.setRelatedId(toUsername);
        debit.setRemark("transfer to " + toUsername + (note != null ? ": " + note : ""));
        debit.setCreatedAt(LocalDateTime.now());
        balenceTransactionRepository.save(debit);

        // 收款记录
        BalenceTransaction credit = new BalenceTransaction();
        credit.setTransactionId(txId);
        credit.setUserUid(toUser.getUid());
        credit.setUserName(toUsername);
        credit.setType("transfer_in");
        credit.setAmount(amount);
        credit.setBalenceAfter(toUser.getBalence());
        credit.setRelatedId(fromUsername);
        credit.setRemark("transfer from " + fromUsername + (note != null ? ": " + note : ""));
        credit.setCreatedAt(LocalDateTime.now());
        balenceTransactionRepository.save(credit);

        log.info("Transfer: {} -> {} amount={} tx={}", fromUsername, toUsername, amount, txId);
        return Map.of(
                "transaction_id", txId,
                "amount", amount,
                "from", fromUsername,
                "to", toUsername,
                "from_balance", fromUser.getBalence(),
                "to_balance", toUser.getBalence()
        );
    }

    public Page<BalenceTransaction> getUserTransactions(String username, int page, int size) {
        User user = userRepository.findByUserName(username).orElse(null);
        if (user == null || user.getUid() == null) return Page.empty();
        return balenceTransactionRepository.findByUserUid(user.getUid(),
                PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt")));
    }

    // ---------- 工具 ----------

    private static <T> Page<T> paginate(List<T> list, PageRequest pr) {
        int start = (int) pr.getOffset();
        int end = Math.min(start + pr.getPageSize(), list.size());
        return new org.springframework.data.domain.PageImpl<>(
                start < list.size() ? list.subList(start, end) : List.of(),
                pr, list.size());
    }
}
