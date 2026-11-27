import React from 'react';
import { Composition } from 'remotion';
import { MainVideo } from './MainVideo';
import { PortraitVideo } from './PortraitVideo';

export const RemotionRoot: React.FC = () => {
  return (
    <>
      <Composition
        id="KebabPortraitVideo"
        component={PortraitVideo}
        durationInFrames={2070}
        fps={30}
        width={1080}
        height={1920}
      />
      <Composition
        id="KebabMotionVideo"
        component={MainVideo}
        durationInFrames={1750}
        fps={30}
        width={1920}
        height={1080}
      />
    </>
  );
};
