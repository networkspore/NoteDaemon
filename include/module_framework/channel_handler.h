// channel_handler.h — Reusable Channel message loop for NoteDaemon modules
//
// C++ equivalent of Java's ChannelWriter + StreamChannel pattern.
// Any module can include this and call run_channel_message_loop() from
// its handle_channel() to read NoteBytes commands from a WebRTC/Unix/TCP
// channel and dispatch them to a command handler.
//
// Usage:
//   Error MyModule::handle_channel(Channel* ch, const std::string& device_id) {
//       return run_channel_message_loop(ch, device_id,
//           [this](const Object& msg, Channel* channel) -> Object {
//               return this->on_channel_message(msg, channel);
//           });
//   }
//
// The handler receives each parsed NoteBytes Object and returns a response
// Object. An empty response is not sent. The loop exits when the channel
// closes or a read error occurs.

#ifndef CHANNEL_HANDLER_H
#define CHANNEL_HANDLER_H

#include <vector>
#include <functional>
#include <cstring>
#include <syslog.h>

#include "notebytes.h"
#include "notebytes_reader.h"
#include "module_framework/channel.h"
#include "module_framework/error.h"

namespace NoteDaemon {

// ═══════════════════════════════════════════════════════════════════════════
// Serialization helpers
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Serialize a NoteBytes Object to wire format bytes.
 * Wire format: [1-byte type=0x0C][4-byte big-endian length][serialized pairs]
 *
 * The result can be sent via Channel::send_arraybuffer() or Channel::write().
 */
inline std::vector<uint8_t> serialize_object_wire(const NoteBytes::Object& obj) {
    auto body = obj.serialize();  // raw pairs, no OBJECT header
    NoteBytes::MetaData meta(NoteBytes::Type::OBJECT, body.size());
    std::vector<uint8_t> wire(NoteBytes::MetaData::SIZE + body.size());
    meta.write_to(wire.data(), 0);
    if (!body.empty()) {
        memcpy(wire.data() + NoteBytes::MetaData::SIZE, body.data(), body.size());
    }
    return wire;
}

/**
 * Write a NoteBytes Object to a Channel.
 * Returns true on success, false on failure.
 */
inline bool write_object_to_channel(Channel* channel, const NoteBytes::Object& obj) {
    if (!channel || !channel->is_open()) return false;
    auto wire = serialize_object_wire(obj);
    // Use send_arraybuffer for remote peers (WebRTC), falls back to write() for fd-based
    channel->send_arraybuffer(wire.data(), wire.size());
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// Response builders
// ═══════════════════════════════════════════════════════════════════════════

inline NoteBytes::Object make_error_response(
    const std::string& cmd, const std::string& error_msg)
{
    NoteBytes::Object resp;
    resp.add(NoteBytes::Value("cmd"),    NoteBytes::Value(cmd));
    resp.add(NoteBytes::Value("status"), NoteBytes::Value("error"));
    resp.add(NoteBytes::Value("error"),  NoteBytes::Value(error_msg));
    return resp;
}

inline NoteBytes::Object make_success_response(const std::string& cmd) {
    NoteBytes::Object resp;
    resp.add(NoteBytes::Value("cmd"),    NoteBytes::Value(cmd));
    resp.add(NoteBytes::Value("status"), NoteBytes::Value("ok"));
    return resp;
}

inline NoteBytes::Object make_success_response(
    const std::string& cmd, const std::string& extra_key, const NoteBytes::Value& extra_val)
{
    NoteBytes::Object resp = make_success_response(cmd);
    resp.add(NoteBytes::Value(extra_key), extra_val);
    return resp;
}

// ═══════════════════════════════════════════════════════════════════════════
// Command handler signature
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Signature for a channel command handler.
 *
 * Takes the parsed message Object and the Channel, returns a response Object.
 * Return an empty Object (size() == 0) to suppress sending a response.
 */
using ChannelCommandHandler = std::function<NoteBytes::Object(
    const NoteBytes::Object& message, Channel* channel)>;

// ═══════════════════════════════════════════════════════════════════════════
// Main message loop
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Run a channel message loop.
 *
 * Reads NoteBytes Objects from the channel's readable fd (the read end of
 * the WebRTC pipe), dispatches each to the provided handler, and writes
 * responses back over the channel.
 *
 * The loop exits when:
 *   - the channel closes (normal shutdown)
 *   - a read error occurs (peer disconnected)
 *   - a protocol error occurs (invalid NoteBytes framing)
 *
 * @param channel   The channel to read from / write to
 * @param device_id Device identifier for logging
 * @param handler   Callback that receives each message and returns a response
 * @return Error::SUCCESS on clean exit, error code on failure
 */
inline Error run_channel_message_loop(
    Channel* channel,
    const std::string& device_id,
    ChannelCommandHandler handler)
{
    if (!channel) {
        return Error::from_code(ErrorCodes::INVALID_STATE, "Null channel");
    }

    int fd = channel->fd();
    if (fd < 0) {
        return Error::from_code(ErrorCodes::INVALID_STATE,
            "Channel has no readable fd (type=" + channel->channel_type() + ")");
    }

    syslog(LOG_INFO, "[ChannelLoop] Start: device=%s type=%s fd=%d",
           device_id.c_str(), channel->channel_type().c_str(), fd);

    try {
        NoteBytes::Reader reader(fd);

        while (channel->is_open()) {
            NoteBytes::Object msg;
            try {
                msg = reader.read_object();
            } catch (const std::runtime_error& e) {
                if (!channel->is_open()) break;  // normal close
                syslog(LOG_WARNING, "[ChannelLoop] read error: %s", e.what());
                break;
            }

            // Dispatch to handler
            NoteBytes::Object response = handler(msg, channel);

            // Send response if the handler produced one
            if (response.size() > 0) {
                write_object_to_channel(channel, response);
            }
        }
    } catch (const std::exception& e) {
        syslog(LOG_ERR, "[ChannelLoop] fatal error: %s", e.what());
        return Error::from_code(ErrorCodes::UNKNOWN,
            std::string("Channel loop error: ") + e.what());
    }

    syslog(LOG_INFO, "[ChannelLoop] End: device=%s", device_id.c_str());
    return Error(ErrorCodes::SUCCESS, "");
}

} // namespace NoteDaemon

#endif // CHANNEL_HANDLER_H
