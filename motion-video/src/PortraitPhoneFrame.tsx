import React from 'react';
import { Video, staticFile } from 'remotion';

export const PortraitPhoneFrame: React.FC<{
  videoSrc: string;
  glowColor?: string;
  style?: React.CSSProperties;
}> = ({ videoSrc, glowColor = '#00e5db', style = {} }) => {
  return (
    <div
      style={{
        width: 760,
        height: 1260,
        borderRadius: 54,
        background: '#0a0a0a',
        padding: 12,
        boxShadow: `0 45px 100px -20px rgba(0,0,0,0.95), 0 0 80px ${glowColor}44, inset 0 0 0 2px #3a3a3a, inset 0 0 0 4px #1c1c1c`,
        position: 'relative',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        border: '3px solid #2a2a2a',
        ...style,
      }}
    >
      {/* Dynamic Island / Speaker Notch */}
      <div
        style={{
          position: 'absolute',
          top: 22,
          left: '50%',
          transform: 'translateX(-50%)',
          width: 140,
          height: 32,
          background: '#000000',
          borderRadius: 24,
          zIndex: 100,
          boxShadow: '0 3px 8px rgba(0,0,0,0.7)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'flex-end',
          paddingRight: 16,
        }}
      >
        <div style={{ width: 12, height: 12, borderRadius: '50%', background: '#0a222c' }} />
      </div>

      {/* Screen Container */}
      <div
        style={{
          width: '100%',
          height: '100%',
          borderRadius: 44,
          overflow: 'hidden',
          position: 'relative',
          background: '#011817',
        }}
      >
        <Video
          src={staticFile(videoSrc)}
          style={{
            width: '100%',
            height: '100%',
            objectFit: 'cover',
          }}
        />
        {/* Subtle Screen Glass Specular Highlight */}
        <div
          style={{
            position: 'absolute',
            inset: 0,
            background: 'linear-gradient(135deg, rgba(255,255,255,0.07) 0%, transparent 40%)',
            pointerEvents: 'none',
          }}
        />
      </div>
    </div>
  );
};
