import React from 'react';
import { Video, staticFile } from 'remotion';

export const PhoneFrame: React.FC<{
  videoSrc: string;
  glowColor?: string;
  style?: React.CSSProperties;
}> = ({ videoSrc, glowColor = '#00e5db', style = {} }) => {
  return (
    <div
      style={{
        width: 440,
        height: 890,
        borderRadius: 52,
        background: '#0a0a0a',
        padding: 12,
        boxShadow: `0 35px 80px -15px rgba(0,0,0,0.85), 0 0 60px ${glowColor}33, inset 0 0 0 2px #333333, inset 0 0 0 4px #1a1a1a`,
        position: 'relative',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        border: '3px solid #262626',
        ...style,
      }}
    >
      {/* Dynamic Island / Speaker Notch */}
      <div
        style={{
          position: 'absolute',
          top: 20,
          left: '50%',
          transform: 'translateX(-50%)',
          width: 110,
          height: 28,
          background: '#000000',
          borderRadius: 20,
          zIndex: 100,
          boxShadow: '0 2px 6px rgba(0,0,0,0.6)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'flex-end',
          paddingRight: 12,
        }}
      >
        <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#081c24' }} />
      </div>

      {/* Screen Container */}
      <div
        style={{
          width: '100%',
          height: '100%',
          borderRadius: 42,
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
            background: 'linear-gradient(135deg, rgba(255,255,255,0.08) 0%, transparent 40%)',
            pointerEvents: 'none',
          }}
        />
      </div>
    </div>
  );
};
