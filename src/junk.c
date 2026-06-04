#include "junk.h"
#include "messages.h"
#include "peer.h"

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/ktime.h>
#include <linux/overflow.h>

static bool jp_valid_len(int len)
{
    return len > 0 && len <= MESSAGE_MAX_SIZE;
}

static int parse_b_tag(char* val, struct list_head* head) {
    int err;
    int i;
    int len;
    u8* pkt;
    struct jp_tag* tag;

    if (!val || strncmp(val, "0x", 2))
        return -EINVAL;
    val += 2;

    len = strlen(val);
    if (len == 0 || len % 2 != 0)
        return -EINVAL;
    len /= 2;
    if (!jp_valid_len(len))
        return -EINVAL;

    pkt = kmalloc(len, GFP_KERNEL);
    if (!pkt)
        return -ENOMEM;

    for (i = len - 1; i >= 0; --i) {
        err = kstrtou8(val + i * 2, 16, pkt + i);
        if (err) {
            err = -EINVAL;
            goto error;
        }

        val[i * 2] = '\0';
    }

    tag = kzalloc(sizeof(*tag), GFP_KERNEL);
    if (!tag) {
        err = -ENOMEM;
        goto error;
    }

    tag->pkt = pkt;
    tag->pkt_size = len;

    list_add(&tag->head, head);
    return 0;

error:
    kfree(pkt);
    return err;
}

static void pkt_counter_modifier(char* buf, int len, struct wg_peer *peer) {
    int val = atomic_read(&peer->jp_packet_counter);
    val = htonl(val);
    memcpy(buf, &val, sizeof(val));
}

static int parse_c_tag(char* val, struct list_head* head) {
    struct jp_tag* tag;

    if (val)
        return -EINVAL;

    tag = kzalloc(sizeof(*tag), GFP_KERNEL);
    if (!tag)
        return -ENOMEM;

    tag->pkt_size = sizeof(u32);
    tag->func = pkt_counter_modifier;

    list_add(&tag->head, head);
    return 0;
}

static void unix_time_modifier(char* buf, int len, struct wg_peer *peer) {
    u32 time = (u32)ktime_get_real_seconds();
    time = htonl(time);
    memcpy(buf, &time, sizeof(time));
}

static int parse_t_tag(char* val, struct list_head* head) {
    struct jp_tag* tag;

    if (val)
        return -EINVAL;

    tag = kzalloc(sizeof(*tag), GFP_KERNEL);
    if (!tag)
        return -ENOMEM;

    tag->pkt_size = sizeof(u32);
    tag->func = unix_time_modifier;

    list_add(&tag->head, head);
    return 0;
}

static void random_byte_modifier(char* buf, int len, struct wg_peer *peer) {
    get_random_bytes(buf, len);
}

static int parse_r_tag(char* val, struct list_head* head) {
    struct jp_tag* tag;
    int len;

    if (!val || 0 > kstrtoint(val, 10, &len) || !jp_valid_len(len))
        return -EINVAL;

    tag = kzalloc(sizeof(*tag), GFP_KERNEL);
    if (!tag)
        return -ENOMEM;

    tag->pkt_size = len;
    tag->func = random_byte_modifier;

    list_add(&tag->head, head);
    return 0;
}

#define ALPHABET_LEN 26
#define LETTER_LEN (ALPHABET_LEN * 2)

static void random_char_modifier(char* buf, int len, struct wg_peer *peer) {
    int i;
    u32 byte;

    for (i = 0; i < len; ++i) {
        byte = get_random_u32() % LETTER_LEN;
        buf[i] = (byte < ALPHABET_LEN) ? 'a' + byte : 'A' + byte - ALPHABET_LEN;
    }
}

static int parse_rc_tag(char* val, struct list_head* head) {
    struct jp_tag* tag;
    int len;

    if (!val || 0 > kstrtoint(val, 10, &len) || !jp_valid_len(len))
        return -EINVAL;

    tag = kzalloc(sizeof(*tag), GFP_KERNEL);
    if (!tag)
        return -ENOMEM;

    tag->pkt_size = len;
    tag->func = random_char_modifier;

    list_add(&tag->head, head);
    return 0;
}

#define DIGIT_LEN 10

static void random_digit_modifier(char* buf, int len, struct wg_peer *peer) {
    int i;

    for (i = 0; i < len; ++i)
        buf[i] = '0' + get_random_u32() % DIGIT_LEN;
}

static int parse_rd_tag(char* val, struct list_head* head) {
    struct jp_tag* tag;
    int len;

    if (!val || 0 > kstrtoint(val, 10, &len) || !jp_valid_len(len))
        return -EINVAL;

    tag = kzalloc(sizeof(*tag), GFP_KERNEL);
    if (!tag)
        return -ENOMEM;

    tag->pkt_size = len;
    tag->func = random_digit_modifier;

    list_add(&tag->head, head);
    return 0;
}

int jp_parse_tags(char* str, struct list_head* head) {
    int err = 0;
    char* key;
    char* val;

    while (true)
    {
        strsep(&str, "<");
        val = strsep(&str, ">");
        if (!val)
            break;

        key = strsep(&val, " ");

        if (!strcmp(key, "b")) {
            err = parse_b_tag(val, head);
            if (err)
                return err;
        }
        else if (!strcmp(key, "c")) {
            err = parse_c_tag(val, head);
            if (err)
                return err;
        }
        else if (!strcmp(key, "t")) {
            err = parse_t_tag(val, head);
            if (err)
                return err;
        }
        else if (!strcmp(key, "r")) {
            err = parse_r_tag(val, head);
            if (err)
                return err;
        }
        else if (!strcmp(key, "rc")) {
            err = parse_rc_tag(val, head);
            if (err)
                return err;
        }
        else if (!strcmp(key, "rd")) {
            err = parse_rd_tag(val, head);
            if (err)
                return err;
        }
        else
            return -EINVAL;
    }

    return 0;
}

void jp_tag_free(struct jp_tag* tag) {
    kfree(tag->pkt);
}

static void jp_spec_clear(struct jp_spec *spec)
{
    kfree(spec->desc);
    spec->desc = NULL;
    kfree(spec->pkt);
    spec->pkt = NULL;
    kfree(spec->mods);
    spec->mods = NULL;
    spec->pkt_size = 0;
    spec->mods_size = 0;
}

void jp_spec_free(struct jp_spec *spec) {
    mutex_lock(&spec->lock);
    jp_spec_clear(spec);
    mutex_unlock(&spec->lock);
}

static int jp_spec_build(const char *desc, u8 **pkt,
                         struct jp_modifier **mods, int *pkt_size,
                         int *mods_size) {
    int err = 0;
    size_t total_pkt_size, total_mods_size, built_pkt_size;
    struct jp_tag *tag, *tmp;
    struct jp_modifier *mod;
    char* buf;
    u8 *new_pkt = NULL;
    struct jp_modifier *new_mods = NULL;
    LIST_HEAD(head);

    *pkt = NULL;
    *mods = NULL;
    *pkt_size = 0;
    *mods_size = 0;

    if (desc == NULL)
        return 0;

    buf = kstrdup(desc, GFP_KERNEL);
    if (!buf) {
        err = -ENOMEM;
        goto error;
    }

    err = jp_parse_tags(buf, &head);
    if (err)
        goto error;

    total_pkt_size = 0;
    total_mods_size = 0;

    list_for_each_entry(tag, &head, head) {
        if (check_add_overflow(total_pkt_size, (size_t)tag->pkt_size,
                               &total_pkt_size)) {
            err = -EINVAL;
            goto error;
        }

        if (tag->func)
            ++total_mods_size;
    }

    if (total_pkt_size > MESSAGE_MAX_SIZE || total_mods_size > MESSAGE_MAX_SIZE) {
        err = -EINVAL;
        goto error;
    }

    if (total_pkt_size) {
        new_pkt = kzalloc(total_pkt_size, GFP_KERNEL);
        if (!new_pkt) {
            err = -ENOMEM;
            goto error;
        }
    }
    if (total_mods_size) {
        new_mods = kcalloc(total_mods_size, sizeof(*new_mods), GFP_KERNEL);
        if (!new_mods) {
            err = -ENOMEM;
            goto error;
        }
    }

    built_pkt_size = 0;
    *mods_size = 0;
    list_for_each_entry_reverse(tag, &head, head) {
        if ((size_t)tag->pkt_size > total_pkt_size - built_pkt_size) {
            err = -EINVAL;
            goto error;
        }

        if (tag->pkt)
            memcpy(new_pkt + built_pkt_size, tag->pkt, tag->pkt_size);

        if (tag->func) {
            mod = new_mods + *mods_size;
            mod->func = tag->func;
            mod->buf = new_pkt + built_pkt_size;
            mod->buf_len = tag->pkt_size;
            ++*mods_size;
        }

        built_pkt_size += tag->pkt_size;
    }
    if (built_pkt_size != total_pkt_size) {
        err = -EINVAL;
        goto error;
    }

    *pkt = new_pkt;
    *mods = new_mods;
    *pkt_size = (int)total_pkt_size;
    new_pkt = NULL;
    new_mods = NULL;

error:
    list_for_each_entry_safe(tag, tmp, &head, head) {
        jp_tag_free(tag);
        list_del(&tag->head);
        kfree(tag);
    }
    kfree(buf);
    kfree(new_pkt);
    kfree(new_mods);
    return err;
}

int jp_spec_replace_desc(struct jp_spec *spec, char *desc)
{
    int err, pkt_size, mods_size;
    u8 *pkt;
    struct jp_modifier *mods;

    err = jp_spec_build(desc, &pkt, &mods, &pkt_size, &mods_size);
    if (err) {
        kfree(desc);
        return err;
    }

    mutex_lock(&spec->lock);
    jp_spec_clear(spec);
    spec->desc = desc;
    spec->pkt = pkt;
    spec->mods = mods;
    spec->pkt_size = pkt_size;
    spec->mods_size = mods_size;
    mutex_unlock(&spec->lock);
    return 0;
}

int jp_spec_setup(struct jp_spec *spec) {
    int err, pkt_size, mods_size;
    u8 *pkt;
    struct jp_modifier *mods;

    mutex_lock(&spec->lock);

    err = jp_spec_build(spec->desc, &pkt, &mods, &pkt_size, &mods_size);
    if (err) {
        mutex_unlock(&spec->lock);
        return err;
    }

    kfree(spec->pkt);
    kfree(spec->mods);
    spec->pkt = pkt;
    spec->mods = mods;
    spec->pkt_size = pkt_size;
    spec->mods_size = mods_size;
    mutex_unlock(&spec->lock);
    return 0;
}

void jp_spec_applymods(struct jp_spec* spec, struct wg_peer* peer) {
    int i;
    struct jp_modifier* mod;

    for (i = 0; i < spec->mods_size; i++) {
        mod = &spec->mods[i];
        if(mod->func && mod->buf_len > 0)
            mod->func(mod->buf, mod->buf_len, peer);
    }
}
