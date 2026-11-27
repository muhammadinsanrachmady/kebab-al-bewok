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
import { PortraitPhoneFrame } from './PortraitPhoneFrame';

export const PortraitVideo: React.FC = () => {
  return (
    <div
      style={{
        flex: 1,
        width: 1080,
        height: 1920,
        backgroundColor: '#011211',
        position: 'relative',
        overflow: 'hidden',
        fontFamily: "'Plus Jakarta Sans', system-ui, -apple-system, sans-serif",
      }}
    >
      {/* SCENE 1: CUSTOMER APP (Sarah) - 0 to 570 frames (~19.0s) */}
      <Sequence from={0} durationInFrames={570}>
        <SceneCustomerPortrait />
        <Audio src={staticFile('natural1.mp3')} volume={1} />
      </Sequence>

      {/* SCENE 2: KITCHEN POS & SIZZLE (Mas Budi) - 570 to 1080 frames (~17.0s) */}
      <Sequence from={570} durationInFrames={510}>
        <SceneKitchenPortrait />
        <Audio src={staticFile('natural2.mp3')} volume={1} />
      </Sequence>

      {/* SCENE 3: DRIVER RADAR & EXACT ROAD MAP (Bang Bewok) - 1080 to 1530 frames (~15.0s) */}
      <Sequence from={1080} durationInFrames={450}>
        <SceneDriverPortrait />
        <Audio src={staticFile('natural3.mp3')} volume={1} />
      </Sequence>

      {/* SCENE 4: LIVE TRACKING & FINALE - 1530 to 2070 frames (~18.0s) */}
      <Sequence from={1530} durationInFrames={540}>
        <SceneFinalePortrait />
        <Audio src={staticFile('natural4.mp3')} volume={1} />
      </Sequence>
    </div>
  );
};

// ============================================================================
// SCENE 1: CUSTOMER APP PORTRAIT
// ============================================================================
const SceneCustomerPortrait: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const scale = spring({ frame, fps, config: { damping: 14 } });
  const rotateY = interpolate(frame, [0, 80, 280, 500], [10, 0, -3, 0], { extrapolateRight: 'clamp' });
  const rotateX = interpolate(frame, [0, 80, 280, 500], [-5, 0, 3, 0], { extrapolateRight: 'clamp' });
  const translateY = interpolate(frame, [0, 100, 250, 450], [40, -10, 10, 0], { extrapolateRight: 'clamp' });

  const pillOpacity = interpolate(frame, [10, 30], [0, 1], { extrapolateRight: 'clamp' });
  const pillY = interpolate(frame, [10, 30], [20, 0], { extrapolateRight: 'clamp' });
  const bgGlow = interpolate(frame, [0, 285, 570], [0.35, 0.6, 0.35]);

  return (
    <div
      style={{
        width: '100%',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        position: 'relative',
        perspective: 1200,
      }}
    >
      {/* Ambient Red Glow */}
      <div
        style={{
          position: 'absolute',
          top: 300,
          width: 800,
          height: 800,
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(220, 38, 38, 0.35) 0%, rgba(245, 158, 11, 0.15) 50%, transparent 70%)',
          filter: 'blur(90px)',
          opacity: bgGlow,
        }}
      />

      {/* Floating Top Badge Pill */}
      <div
        style={{
          position: 'absolute',
          top: 90,
          opacity: pillOpacity,
          transform: `translateY(${pillY}px)`,
          background: 'rgba(1, 38, 36, 0.90)',
          backdropFilter: 'blur(16px)',
          border: '1.5px solid rgba(239, 68, 68, 0.6)',
          borderRadius: 40,
          padding: '14px 32px',
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          boxShadow: '0 20px 40px rgba(0,0,0,0.6)',
          zIndex: 50,
        }}
      >
        <span style={{ width: 12, height: 12, borderRadius: '50%', background: '#ef4444', boxShadow: '0 0 12px #ef4444' }} />
        <span style={{ color: '#ffffff', fontWeight: 900, fontSize: 20, letterSpacing: '1px' }}>
          PERAN 1 : SARAH • PEMESANAN APLIKASI
        </span>
      </div>

      {/* 3D Phone Frame */}
      <div
        style={{
          transform: `scale(${scale}) translateY(${translateY - 40}px) rotateY(${rotateY}deg) rotateX(${rotateX}deg)`,
          transformOrigin: '50% 50%',
          transition: 'transform 0.05s ease-out',
        }}
      >
        <PortraitPhoneFrame videoSrc="portrait_clip1.mp4" glowColor="#ef4444" />
      </div>

      {/* Bottom Subtitle Card */}
      <div
        style={{
          position: 'absolute',
          bottom: 70,
          left: 60,
          right: 60,
          background: 'rgba(1, 32, 30, 0.88)',
          backdropFilter: 'blur(20px)',
          border: '1.5px solid rgba(245, 158, 11, 0.45)',
          borderRadius: 28,
          padding: '24px 30px',
          boxShadow: '0 25px 60px rgba(0,0,0,0.7)',
          zIndex: 50,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
          <span style={{ fontSize: 18 }}>👩‍🦰</span>
          <span style={{ color: '#fbbf24', fontWeight: 800, fontSize: 18, letterSpacing: '0.5px' }}>
            Sarah (Customer)
          </span>
        </div>
        <p style={{ margin: 0, color: '#f8fafc', fontSize: 21, fontWeight: 700, lineHeight: 1.4 }}>
          "Wah, laper banget nih... Pengen yang gurih dan kejunya lumer! Untung ada aplikasi Kebab AL Bewok, langsung checkout!"
        </p>
      </div>
    </div>
  );
};

// ============================================================================
// SCENE 2: KITCHEN POS & KANBAN PORTRAIT
// ============================================================================
const SceneKitchenPortrait: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const scale = spring({ frame, fps, config: { damping: 14 } });
  const rotateY = interpolate(frame, [0, 80, 260, 480], [-10, 0, 4, 0], { extrapolateRight: 'clamp' });
  const rotateX = interpolate(frame, [0, 80, 260, 480], [5, 0, -3, 0], { extrapolateRight: 'clamp' });
  const translateY = interpolate(frame, [0, 100, 250, 450], [30, -10, 5, 0], { extrapolateRight: 'clamp' });

  const pillOpacity = interpolate(frame, [10, 30], [0, 1], { extrapolateRight: 'clamp' });
  const pillY = interpolate(frame, [10, 30], [20, 0], { extrapolateRight: 'clamp' });

  return (
    <div
      style={{
        width: '100%',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        position: 'relative',
        perspective: 1200,
      }}
    >
      {/* Ambient Amber Glow */}
      <div
        style={{
          position: 'absolute',
          top: 300,
          width: 800,
          height: 800,
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(245, 158, 11, 0.35) 0%, rgba(220, 38, 38, 0.15) 50%, transparent 70%)',
          filter: 'blur(90px)',
        }}
      />

      {/* Floating Top Badge Pill */}
      <div
        style={{
          position: 'absolute',
          top: 90,
          opacity: pillOpacity,
          transform: `translateY(${pillY}px)`,
          background: 'rgba(1, 38, 36, 0.90)',
          backdropFilter: 'blur(16px)',
          border: '1.5px solid rgba(245, 158, 11, 0.6)',
          borderRadius: 40,
          padding: '14px 32px',
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          boxShadow: '0 20px 40px rgba(0,0,0,0.6)',
          zIndex: 50,
        }}
      >
        <span style={{ width: 12, height: 12, borderRadius: '50%', background: '#f59e0b', boxShadow: '0 0 12px #f59e0b' }} />
        <span style={{ color: '#ffffff', fontWeight: 900, fontSize: 20, letterSpacing: '1px' }}>
          PERAN 2 : MAS BUDI • DAPUR & POS KASIR LAPAK
        </span>
      </div>

      {/* 3D Phone Frame */}
      <div
        style={{
          transform: `scale(${scale}) translateY(${translateY - 40}px) rotateY(${rotateY}deg) rotateX(${rotateX}deg)`,
          transformOrigin: '50% 50%',
          transition: 'transform 0.05s ease-out',
        }}
      >
        <PortraitPhoneFrame videoSrc="portrait_clip2.mp4" glowColor="#f59e0b" />
      </div>

      {/* Bottom Subtitle Card */}
      <div
        style={{
          position: 'absolute',
          bottom: 70,
          left: 60,
          right: 60,
          background: 'rgba(1, 32, 30, 0.88)',
          backdropFilter: 'blur(20px)',
          border: '1.5px solid rgba(245, 158, 11, 0.45)',
          borderRadius: 28,
          padding: '24px 30px',
          boxShadow: '0 25px 60px rgba(0,0,0,0.7)',
          zIndex: 50,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
          <span style={{ fontSize: 18 }}>👨‍🍳</span>
          <span style={{ color: '#fbbf24', fontWeight: 800, fontSize: 18, letterSpacing: '0.5px' }}>
            Mas Budi (Koki & Kasir)
          </span>
        </div>
        <p style={{ margin: 0, color: '#f8fafc', fontSize: 21, fontWeight: 700, lineHeight: 1.4 }}>
          "Nah, ada orderan masuk di dapur! Kebab Cheesy Lava Jumbo buat Kak Sarah. Langsung kita racik, panggang renyah, pesanan matang panggil kurir!"
        </p>
      </div>
    </div>
  );
};

// ============================================================================
// SCENE 3: DRIVER RADAR & EXACT ROAD MAP PORTRAIT
// ============================================================================
const SceneDriverPortrait: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const scale = spring({ frame, fps, config: { damping: 14 } });
  const rotateY = interpolate(frame, [0, 80, 220, 420], [8, -3, 4, 0], { extrapolateRight: 'clamp' });
  const rotateX = interpolate(frame, [0, 80, 220, 420], [-4, 4, -2, 0], { extrapolateRight: 'clamp' });
  const translateY = interpolate(frame, [0, 80, 200, 400], [20, -10, 0, 0], { extrapolateRight: 'clamp' });

  const pillOpacity = interpolate(frame, [10, 30], [0, 1], { extrapolateRight: 'clamp' });
  const pillY = interpolate(frame, [10, 30], [20, 0], { extrapolateRight: 'clamp' });

  return (
    <div
      style={{
        width: '100%',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        position: 'relative',
        perspective: 1200,
      }}
    >
      {/* Ambient Emerald Glow */}
      <div
        style={{
          position: 'absolute',
          top: 300,
          width: 800,
          height: 800,
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(16, 185, 129, 0.35) 0%, rgba(6, 78, 59, 0.2) 50%, transparent 70%)',
          filter: 'blur(90px)',
        }}
      />

      {/* Floating Top Badge Pill */}
      <div
        style={{
          position: 'absolute',
          top: 90,
          opacity: pillOpacity,
          transform: `translateY(${pillY}px)`,
          background: 'rgba(1, 38, 36, 0.90)',
          backdropFilter: 'blur(16px)',
          border: '1.5px solid rgba(16, 185, 129, 0.6)',
          borderRadius: 40,
          padding: '14px 32px',
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          boxShadow: '0 20px 40px rgba(0,0,0,0.6)',
          zIndex: 50,
        }}
      >
        <span style={{ width: 12, height: 12, borderRadius: '50%', background: '#10b981', boxShadow: '0 0 12px #10b981' }} />
        <span style={{ color: '#ffffff', fontWeight: 900, fontSize: 20, letterSpacing: '1px' }}>
          PERAN 3 : BANG BEWOK • RADAR & PETA NAVIGASI KURIR
        </span>
      </div>

      {/* 3D Phone Frame */}
      <div
        style={{
          transform: `scale(${scale}) translateY(${translateY - 40}px) rotateY(${rotateY}deg) rotateX(${rotateX}deg)`,
          transformOrigin: '50% 50%',
          transition: 'transform 0.05s ease-out',
        }}
      >
        <PortraitPhoneFrame videoSrc="portrait_clip3.mp4" glowColor="#10b981" />
      </div>

      {/* Bottom Subtitle Card */}
      <div
        style={{
          position: 'absolute',
          bottom: 70,
          left: 60,
          right: 60,
          background: 'rgba(1, 32, 30, 0.88)',
          backdropFilter: 'blur(20px)',
          border: '1.5px solid rgba(16, 185, 129, 0.45)',
          borderRadius: 28,
          padding: '24px 30px',
          boxShadow: '0 25px 60px rgba(0,0,0,0.7)',
          zIndex: 50,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
          <span style={{ fontSize: 18 }}>🛵</span>
          <span style={{ color: '#34d399', fontWeight: 800, fontSize: 18, letterSpacing: '0.5px' }}>
            Bang Bewok (Mitra Driver)
          </span>
        </div>
        <p style={{ margin: 0, color: '#f8fafc', fontSize: 21, fontWeight: 700, lineHeight: 1.4 }}>
          "Sip, notifikasi orderan masuk! Buka aplikasi, ambil orderan. Peta otomatis memandu rute tercepat... Gasspol motor meluncur anget-anget!"
        </p>
      </div>
    </div>
  );
};

// ============================================================================
// SCENE 4: LIVE TRACKING CUSTOMER & FINALE PORTRAIT
// ============================================================================
const SceneFinalePortrait: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const scale = spring({ frame, fps, config: { damping: 14 } });
  const rotateY = interpolate(frame, [0, 100, 300, 500], [-6, 0, 3, 0], { extrapolateRight: 'clamp' });
  const rotateX = interpolate(frame, [0, 100, 300, 500], [4, 0, -2, 0], { extrapolateRight: 'clamp' });

  const pillOpacity = interpolate(frame, [10, 30], [0, 1], { extrapolateRight: 'clamp' });
  const pillY = interpolate(frame, [10, 30], [20, 0], { extrapolateRight: 'clamp' });

  return (
    <div
      style={{
        width: '100%',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        position: 'relative',
        perspective: 1200,
      }}
    >
      {/* Ambient Gold/Cyan Glow */}
      <div
        style={{
          position: 'absolute',
          top: 300,
          width: 800,
          height: 800,
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(245, 158, 11, 0.35) 0%, rgba(6, 182, 212, 0.2) 50%, transparent 70%)',
          filter: 'blur(90px)',
        }}
      />

      {/* Floating Top Badge Pill */}
      <div
        style={{
          position: 'absolute',
          top: 90,
          opacity: pillOpacity,
          transform: `translateY(${pillY}px)`,
          background: 'rgba(1, 38, 36, 0.90)',
          backdropFilter: 'blur(16px)',
          border: '1.5px solid rgba(245, 158, 11, 0.6)',
          borderRadius: 40,
          padding: '14px 32px',
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          boxShadow: '0 20px 40px rgba(0,0,0,0.6)',
          zIndex: 50,
        }}
      >
        <span style={{ width: 12, height: 12, borderRadius: '50%', background: '#f59e0b', boxShadow: '0 0 12px #f59e0b' }} />
        <span style={{ color: '#ffffff', fontWeight: 900, fontSize: 20, letterSpacing: '1px' }}>
          PESANAN TIBA • KEBAB AL BEWOK RESMI
        </span>
      </div>

      {/* 3D Phone Frame */}
      <div
        style={{
          transform: `scale(${scale}) translateY(-40px) rotateY(${rotateY}deg) rotateX(${rotateX}deg)`,
          transformOrigin: '50% 50%',
          transition: 'transform 0.05s ease-out',
        }}
      >
        <PortraitPhoneFrame videoSrc="portrait_clip4.mp4" glowColor="#f59e0b" />
      </div>

      {/* Bottom Subtitle Card */}
      <div
        style={{
          position: 'absolute',
          bottom: 70,
          left: 60,
          right: 60,
          background: 'rgba(1, 32, 30, 0.88)',
          backdropFilter: 'blur(20px)',
          border: '1.5px solid rgba(245, 158, 11, 0.45)',
          borderRadius: 28,
          padding: '24px 30px',
          boxShadow: '0 25px 60px rgba(0,0,0,0.7)',
          zIndex: 50,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
          <span style={{ fontSize: 18 }}>🌯</span>
          <span style={{ color: '#fbbf24', fontWeight: 800, fontSize: 18, letterSpacing: '0.5px' }}>
            Sarah (Customer)
          </span>
        </div>
        <p style={{ margin: 0, color: '#f8fafc', fontSize: 21, fontWeight: 700, lineHeight: 1.4 }}>
          "Wih, di petaku posisi kurirnya udah deket banget... Wah, cepet banget sampainya! Masih hangat dan kejunya lumer. Pesan sekarang di albewok.my.id!"
        </p>
      </div>
    </div>
  );
};
