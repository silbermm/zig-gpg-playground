const std = @import("std");

const c = @cImport({
    @cInclude("errno.h");
    @cInclude("locale.h");
    @cInclude("unistd.h");
    @cInclude("gpgme.h");
    @cDefine("SIZE", "4092");
});

pub fn main() anyerror!void {
    var p = c.gpgme_check_version(null);
    std.log.info("version={s}", .{p});

    const t = c.gpgme_set_locale(null, c.LC_CTYPE, c.setlocale(c.LC_CTYPE, null));
    std.log.info("set_locale result={}", .{t});

    // check for OpenPGP support
    var err = c.gpgme_engine_check_version(c.gpgme_protocol_t.GPGME_PROTOCOL_OpenPGP);
    if (err != c.GPG_ERR_NO_ERROR) {
        std.log.err("ERROR.", .{});
        return;
    }

    p = c.gpgme_get_protocol_name(c.gpgme_protocol_t.GPGME_PROTOCOL_OpenPGP);
    std.log.info("Protocol name: {s}", .{p});

    // get engine information
    var enginfo: c.gpgme_engine_info_t = undefined;
    err = c.gpgme_get_engine_info(&enginfo);

    if (err != c.GPG_ERR_NO_ERROR) {
        std.log.err("ERROR {}", .{err});
        return;
    }
    std.log.info("file={s}", .{enginfo.*.file_name});

    // Create a context
    var ceofcontext: c.gpgme_ctx_t = undefined;
    err = c.gpgme_new(&ceofcontext);

    if (err != c.GPG_ERR_NO_ERROR) {
        std.log.err("ERROR {}", .{err});
        return;
    }

    // set protocol to use in our context
    err = c.gpgme_set_protocol(ceofcontext, c.gpgme_protocol_t.GPGME_PROTOCOL_OpenPGP);
    if (err != c.GPG_ERR_NO_ERROR) {
        std.log.err("ERROR {}", .{err});
        return;
    }

    // set engine info in our context
    err = c.gpgme_ctx_set_engine_info(ceofcontext, c.gpgme_protocol_t.GPGME_PROTOCOL_OpenPGP, "/usr/bin/gpg2", "/home/silbermm/.gnupg/");
    if (err != c.GPG_ERR_NO_ERROR) {
        std.log.err("ERROR {}", .{err});
        return;
    }

    // do ascii armor data, so output is readable in console
    _ = c.gpgme_set_armor(ceofcontext, 1);

    // create buffer for data exchange with gpgme
    var data: c.gpgme_data_t = undefined;
    err = c.gpgme_data_new(&data);
    if (err != c.GPG_ERR_NO_ERROR) {
        std.log.err("ERROR {}", .{err});
        return;
    }

    err = c.gpgme_data_set_encoding(data, c.gpgme_data_encoding_t.GPGME_DATA_ENCODING_ARMOR);
    if (err != c.GPG_ERR_NO_ERROR) return;

    // EXPORT AND GET PUBLIC KEY
    err = c.gpgme_op_export(ceofcontext, null, 0, data);
    if (err != c.GPG_ERR_NO_ERROR) return;

    var read_bytes = c.gpgme_data_seek(data, 0, c.SEEK_END);

    std.log.info("end is={}", .{read_bytes});
    if (read_bytes == -1) {
        std.log.err("data-seek-err: {}", .{12});
        return;
    }

    read_bytes = c.gpgme_data_seek(data, 0, c.SEEK_SET);
    std.log.info("start is={} (should be 0)", .{read_bytes});

    var buf: [c.SIZE]u8 = undefined;
    var read_new_bytes = c.gpgme_data_read(data, &buf, c.SIZE);
    while (read_new_bytes > 0) {
        read_new_bytes = c.gpgme_data_read(data, &buf, c.SIZE);
    }
    std.log.info("buffer {s}", .{buf});

    // SEARCH FOR A KEY
    var key: c.gpgme_key_t = undefined;
    err = c.gpgme_op_keylist_start(ceofcontext, null, 0);
    while (err == c.GPG_ERR_NO_ERROR) {
        err = c.gpgme_op_keylist_next(ceofcontext, &key);
        if (err != c.GPG_ERR_NO_ERROR) break;

        var res = c.gpgme_key_get_string_attr(key, c.gpgme_attr_t.GPGME_ATTR_FPR, null, 0);
        std.log.info("fingerprint {s}", .{res});

        // ENCRYPT SOME DATA
        var cipher: c.gpgme_data_t = undefined;
        err = c.gpgme_data_new(&cipher);
        var to_encrypt: c.gpgme_data_t = undefined;

        err = c.gpgme_data_new_from_mem(&to_encrypt, "text\n", 5, 0);
        var keys = [_]c.gpgme_key_t{ key, null };

        _ = c.gpgme_op_encrypt(ceofcontext, &keys, c.gpgme_encrypt_flags_t.GPGME_ENCRYPT_ALWAYS_TRUST, to_encrypt, cipher);

        const result = c.gpgme_op_encrypt_result(ceofcontext);

        // READ THE ENCRYPTED DATA
        var d: [c.SIZE]u8 = undefined;
        read_bytes = c.gpgme_data_seek(cipher, 0, c.SEEK_SET);
        var read_new_bytes_2 = c.gpgme_data_read(cipher, &d, c.SIZE);
        while (read_new_bytes_2 > 0) {
            read_new_bytes_2 = c.gpgme_data_read(cipher, &d, c.SIZE);
        }
        std.log.info("DATA: {s}", .{d});

        // TRY TO DECRYPT THE DATA
        var decrypted: c.gpgme_data_t = undefined;
        err = c.gpgme_data_new(&decrypted);

        _ = c.gpgme_data_rewind(cipher);

        err = c.gpgme_op_decrypt(ceofcontext, cipher, decrypted);
        if (err != c.GPG_ERR_NO_ERROR) {
            std.log.err("unable to decrpyt {}", .{err});
        }

        // READ THE DECRYPTED DATA
        var text: [c.SIZE]u8 = undefined;
        read_bytes = c.gpgme_data_seek(decrypted, 0, c.SEEK_SET);
        var read_new_bytes_3 = c.gpgme_data_read(decrypted, &text, c.SIZE);
        while (read_new_bytes_3 > 0) {
            //_ = try w.print("{s}", .{text});
            read_new_bytes_3 = c.gpgme_data_read(decrypted, &text, c.SIZE);
        }
        std.log.info("TEXT: {s}", .{text});

        // RELEASE THE POINTERS
        c.gpgme_data_release(to_encrypt);
        c.gpgme_data_release(cipher);
        c.gpgme_data_release(decrypted);
        c.gpgme_key_release(key);
    }

    // RELEASE THE REST
    c.gpgme_data_release(data);
    c.gpgme_release(ceofcontext);
}
