import React from 'react';
import {
  Sequence,
  Audio,
  staticFile,
  interpolate,
  spring,
  useCurrentFrame,
  useVideoConfig,
} from 'remotion';
import { PhoneFrame } from './PhoneFrame';

export const MainVideo: React.FC = () => {
  return (
    <div
      style={{
        flex: 1,
        width: 1920,
        height: 1080,
        backgroundColor: '#011211',
        position: 'relative',
        overflow: 'hidden',
        fontFamily: "'Plus Jakarta Sans', system-ui, -apple-system, sans-serif",
      }}
    >
      {/* SCENE 1: CUSTOMER APP (Sarah) - 0 to 460 frames (~15.3s) */}
      <Sequence from={0} durationInFrames={460}>
        <SceneCustomer />
        <Audio src={staticFile('audio1.mp3')} volume={1} />
      </Sequence>

      {/* SCENE 2: KITCHEN POS & SIZZLE (Mas Budi) - 460 to 930 frames (~15.7s) */}
      <Sequence from={460} durationInFrames={470}>
        <SceneKitchen />
        <Audio src={staticFile('audio2.mp3')} volume={1} />
      </Sequence>

      {/* SCENE 3: DRIVER RADAR & ESRI LIVE MAP (Bang Bewok) - 930 to 1315 frames (~12.8s) */}
      <Sequence from={930} durationInFrames={385}>
        <SceneDriver />
        <Audio src={staticFile('audio3.mp3')} volume={1} />
      </Sequence>

      {/* SCENE 4: LIVE TRACKING & FINALE - 1315 to 1750 frames (~14.5s) */}
      <Sequence from={1315} durationInFrames={435}>
        <SceneFinale />
        <Audio src={staticFile('audio4.mp3')} volume={1} />
      </Sequence>
    </div>
  );
};

// ============================================================================
// SCENE 1: CUSTOMER APP MOTION
// ============================================================================
const SceneCustomer: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  // Entrance spring
  const scale = spring({ frame, fps, config: { damping: 14 } });
  const rotateY = interpolate(frame, [0, 60, 200, 360], [18, 0, -4, 0], {
    extrapolateRight: 'clamp',
  });
  const rotateX = interpolate(frame, [0, 60, 200, 360], [-8, 0, 4, 0], {
    extrapolateRight: 'clamp',
  });

  // Camera zoom into menu & modal
  const zoom = interpolate(frame, [0, 80, 160, 260, 380], [1, 1, 1.25, 1.25, 1], {
    extrapolateRight: 'clamp',
  });
  const translateY = interpolate(frame, [80, 160, 260, 380], [0, -120, -120, 0], {
    extrapolateRight: 'clamp',
  });

  // Floating Pill badge entrance
  const pillOpacity = interpolate(frame, [10, 25], [0, 1], { extrapolateRight: 'clamp' });
  const pillY = interpolate(frame, [10, 25], [20, 0], { extrapolateRight: 'clamp' });

  // Floating Ambient background gradient
  const bgGlow = interpolate(frame, [0, 230, 460], [0.3, 0.5, 0.3]);

  return (
    <div
      style={{
        width: '100%',
        height: '100%',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        position: 'relative',
        perspective: 1400,
      }}
    >
      {/* Dynamic Ambient Background */}
      <div
        style={{
          position: 'absolute',
          width: 900,
          height: 900,
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(220, 38, 38, 0.25) 0%, rgba(245, 158, 11, 0.1) 50%, transparent 70%)',
          filter: 'blur(80px)',
          opacity: bgGlow,
          transform: `translate(${Math.sin(frame / 40) * 40}px, ${Math.cos(frame / 40) * 30}px)`,
        }}
      />

      {/* Floating Kinetic Badge Pill */}
      <div
        style={{
          position: 'absolute',
          top: 70,
          opacity: pillOpacity,
          transform: `translateY(${pillY}px)`,
          background: 'rgba(1, 38, 36, 0.85)',
          backdropFilter: 'blur(16px)',
          border: '1.5px solid rgba(220, 38, 38, 0.5)',
          borderRadius: 40,
          padding: '12px 28px',
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          boxShadow: '0 15px 35px rgba(0,0,0,0.5)',
          zIndex: 50,
        }}
      >
        <span
          style={{
            width: 10,
            height: 10,
            borderRadius: '50%',
            background: '#ef4444',
            boxShadow: '0 0 10px #ef4444',
          }}
        />
        <span style={{ color: '#ffffff', fontWeight: 800, fontSize: 16, letterSpacing: '1px' }}>
          PERAN 1 : SARAH • PEMESANAN APLIKASI CUSTOMER
        </span>
      </div>

      {/* 3D Motion Device Frame */}
      <div
        style={{
          transform: `scale(${scale * zoom}) translateY(${translateY}px) rotateY(${rotateY}deg) rotateX(${rotateX}deg)`,
          transformOrigin: '50% 60%',
          transition: 'transform 0.05s ease-out',
        }}
      >
        <PhoneFrame videoSrc="clip1.mp4" glowColor="#ef4444" />
      </div>

      {/* Subtitle Caption */}
      <div
        style={{
          position: 'absolute',
          bottom: 50,
          background: 'rgba(1, 24, 23, 0.9)',
          backdropFilter: 'blur(12px)',
          border: '1px solid rgba(255,255,255,0.1)',
          borderRadius: 20,
          padding: '14px 32px',
          maxWidth: 900,
          textAlign: 'center',
          color: '#ffffff',
          fontSize: 20,
          fontWeight: 700,
          boxShadow: '0 15px 35px rgba(0,0,0,0.6)',
        }}
      >
        "Duh laper banget nih, pengen makan yang gurih-gurih lumer! Buka aplikasi, pilih Cheesy Lava Jumbo, kunci alamat di peta... langsung checkout!"
      </div>
    </div>
  );
};

// ============================================================================
// SCENE 2: KITCHEN POS & SIZZLE
// ============================================================================
const SceneKitchen: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const scale = spring({ frame, fps, config: { damping: 14 } });
  const rotateY = interpolate(frame, [0, 80, 240, 470], [-12, 0, 6, 0]);
  const rotateX = interpolate(frame, [0, 80, 240, 470], [6, 0, -4, 0]);

  return (
    <div
      style={{
        width: '100%',
        height: '100%',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        position: 'relative',
        perspective: 1400,
      }}
    >
      {/* Kitchen Amber Glow */}
      <div
        style={{
          position: 'absolute',
          width: 900,
          height: 900,
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(245, 158, 11, 0.25) 0%, rgba(16, 185, 129, 0.1) 50%, transparent 70%)',
          filter: 'blur(80px)',
          transform: `translate(${Math.cos(frame / 35) * 40}px, ${Math.sin(frame / 35) * 30}px)`,
        }}
      />

      {/* Floating Kinetic Badge Pill */}
      <div
        style={{
          position: 'absolute',
          top: 70,
          background: 'rgba(1, 38, 36, 0.85)',
          backdropFilter: 'blur(16px)',
          border: '1.5px solid rgba(245, 158, 11, 0.6)',
          borderRadius: 40,
          padding: '12px 28px',
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          boxShadow: '0 15px 35px rgba(0,0,0,0.5)',
          zIndex: 50,
        }}
      >
        <span
          style={{
            width: 10,
            height: 10,
            borderRadius: '50%',
            background: '#f59e0b',
            boxShadow: '0 0 10px #f59e0b',
          }}
        />
        <span style={{ color: '#ffffff', fontWeight: 800, fontSize: 16, letterSpacing: '1px' }}>
          PERAN 2 : MAS BUDI • TERIMA PESANAN & MASAK DI POS LAPAK
        </span>
      </div>

      {/* 3D Device Frame */}
      <div
        style={{
          transform: `scale(${scale}) rotateY(${rotateY}deg) rotateX(${rotateX}deg)`,
        }}
      >
        <PhoneFrame videoSrc="clip2.mp4" glowColor="#f59e0b" />
      </div>

      {/* Subtitle Caption */}
      <div
        style={{
          position: 'absolute',
          bottom: 50,
          background: 'rgba(1, 24, 23, 0.9)',
          backdropFilter: 'blur(12px)',
          border: '1px solid rgba(255,255,255,0.1)',
          borderRadius: 20,
          padding: '14px 32px',
          maxWidth: 900,
          textAlign: 'center',
          color: '#ffffff',
          fontSize: 20,
          fontWeight: 700,
          boxShadow: '0 15px 35px rgba(0,0,0,0.6)',
        }}
      >
        "Ting! Ada pesanan masuk di dapur lapak! Satu Kebab Cheesy Lava Jumbo. Siap kita racik, panggang tortilla garing, daging sapi juicy, dan keju lumer!"
      </div>
    </div>
  );
};

// ============================================================================
// SCENE 3: DRIVER RADAR & REAL ESRI WORLD STREET MAP MOTION
// ============================================================================
const SceneDriver: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const scale = spring({ frame, fps, config: { damping: 14 } });

  // Camera dynamics: Swoop in on the live moving map
  const zoom = interpolate(frame, [0, 60, 180, 340], [1, 1, 1.35, 1.1], {
    extrapolateRight: 'clamp',
  });
  const translateY = interpolate(frame, [0, 60, 180, 340], [0, 0, -140, -40], {
    extrapolateRight: 'clamp',
  });
  const rotateY = interpolate(frame, [0, 80, 220, 385], [15, -4, 6, 0]);
  const rotateX = interpolate(frame, [0, 80, 220, 385], [-6, 6, -2, 0]);

  return (
    <div
      style={{
        width: '100%',
        height: '100%',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        position: 'relative',
        perspective: 1400,
      }}
    >
      {/* Neon Emerald / Cyan GPS Glow */}
      <div
        style={{
          position: 'absolute',
          width: 950,
          height: 950,
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(16, 185, 129, 0.3) 0%, rgba(0, 229, 219, 0.15) 50%, transparent 70%)',
          filter: 'blur(80px)',
          transform: `translate(${Math.sin(frame / 30) * 50}px, ${Math.cos(frame / 30) * 35}px)`,
        }}
      />

      {/* Floating Kinetic Badge Pill with Live Radar Pulse */}
      <div
        style={{
          position: 'absolute',
          top: 70,
          background: 'rgba(1, 38, 36, 0.85)',
          backdropFilter: 'blur(16px)',
          border: '1.5px solid rgba(16, 185, 129, 0.7)',
          borderRadius: 40,
          padding: '12px 28px',
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          boxShadow: '0 15px 35px rgba(16, 185, 129, 0.3)',
          zIndex: 50,
        }}
      >
        <span
          style={{
            width: 12,
            height: 12,
            borderRadius: '50%',
            background: '#10b981',
            boxShadow: '0 0 14px #10b981',
          }}
        />
        <span style={{ color: '#ffffff', fontWeight: 800, fontSize: 16, letterSpacing: '1px' }}>
          PERAN 3 : BANG BEWOK • RADAR KURIR & PETA NAVIGASI ESRI REAL-TIME
        </span>
      </div>

      {/* 3D Device Frame with Dynamic Camera Tracking */}
      <div
        style={{
          transform: `scale(${scale * zoom}) translateY(${translateY}px) rotateY(${rotateY}deg) rotateX(${rotateX}deg)`,
          transformOrigin: '50% 65%',
        }}
      >
        <PhoneFrame videoSrc="clip3.mp4" glowColor="#10b981" />
      </div>

      {/* Subtitle Caption */}
      <div
        style={{
          position: 'absolute',
          bottom: 50,
          background: 'rgba(1, 24, 23, 0.9)',
          backdropFilter: 'blur(12px)',
          border: '1px solid rgba(255,255,255,0.1)',
          borderRadius: 20,
          padding: '14px 32px',
          maxWidth: 900,
          textAlign: 'center',
          color: '#ffffff',
          fontSize: 20,
          fontWeight: 700,
          boxShadow: '0 15px 35px rgba(0,0,0,0.6)',
        }}
      >
        "Notifikasi orderan siap antar! Buka aplikasi kurir, klik ambil order. Peta navigasi rute otomatis memandu jalan tercepat. Gass motor, antar kilat masih panas!"
      </div>
    </div>
  );
};

// ============================================================================
// SCENE 4: REAL CUSTOMER TRACKING & FINALE
// ============================================================================
const SceneFinale: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const scale = spring({ frame, fps, config: { damping: 14 } });
  const rotateY = interpolate(frame, [0, 100, 250, 435], [-8, 0, 4, 0]);

  return (
    <div
      style={{
        width: '100%',
        height: '100%',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        position: 'relative',
        perspective: 1400,
      }}
    >
      {/* Brand Teal Glow */}
      <div
        style={{
          position: 'absolute',
          width: 1000,
          height: 1000,
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(0, 229, 219, 0.25) 0%, rgba(1, 38, 36, 0.4) 60%, transparent 80%)',
          filter: 'blur(80px)',
          transform: `translate(${Math.cos(frame / 40) * 40}px, ${Math.sin(frame / 40) * 30}px)`,
        }}
      />

      {/* Floating Kinetic Badge Pill */}
      <div
        style={{
          position: 'absolute',
          top: 70,
          background: 'rgba(1, 38, 36, 0.85)',
          backdropFilter: 'blur(16px)',
          border: '1.5px solid rgba(0, 229, 219, 0.7)',
          borderRadius: 40,
          padding: '12px 28px',
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          boxShadow: '0 15px 35px rgba(0, 229, 219, 0.3)',
          zIndex: 50,
        }}
      >
        <span
          style={{
            width: 12,
            height: 12,
            borderRadius: '50%',
            background: '#00e5db',
            boxShadow: '0 0 14px #00e5db',
          }}
        />
        <span style={{ color: '#ffffff', fontWeight: 800, fontSize: 16, letterSpacing: '1px' }}>
          PESANAN SAMPAI HANGAT & LUMER • albewok.my.id
        </span>
      </div>

      {/* 3D Device Frame */}
      <div
        style={{
          transform: `scale(${scale}) rotateY(${rotateY}deg)`,
        }}
      >
        <PhoneFrame videoSrc="clip4.mp4" glowColor="#00e5db" />
      </div>

      {/* Subtitle Caption */}
      <div
        style={{
          position: 'absolute',
          bottom: 50,
          background: 'rgba(1, 24, 23, 0.9)',
          backdropFilter: 'blur(12px)',
          border: '1px solid rgba(255,255,255,0.1)',
          borderRadius: 20,
          padding: '14px 32px',
          maxWidth: 900,
          textAlign: 'center',
          color: '#ffffff',
          fontSize: 20,
          fontWeight: 700,
          boxShadow: '0 15px 35px rgba(0,0,0,0.6)',
        }}
      >
        "Wah, di petaku posisi kurirnya kelihatan jalan mendekat! Cepat banget sampainya, aromanya harum dan kejunya bener-bener lumer! Pesan sekarang di albewok.my.id!"
      </div>
    </div>
  );
};
