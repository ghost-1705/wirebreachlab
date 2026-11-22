import React from 'react';
import { DeviceRole } from '../types/simulator';

interface Device3DGraphicProps {
  role: DeviceRole;
  isSelected: boolean;
  isAlert: boolean;
  isPoisoned: boolean;
  defended: boolean;
  isAttacker: boolean;
  isBypassed?: boolean;
}

interface Palette {
  top: string;
  front: string;
  side: string;
  stroke: string;
  accent: string;
  led: string;
  glow: string;
}

function getHardwarePalette({
  isSelected,
  isAlert,
  isPoisoned,
  defended,
  isAttacker,
}: Omit<Device3DGraphicProps, 'role' | 'isBypassed'>): Palette {
  if (isAlert) {
    return {
      top: '#6E1E29',
      front: '#45121A',
      side: '#2C0B10',
      stroke: '#F87171',
      accent: '#FCA5A5',
      led: '#EF4444',
      glow: 'rgba(239, 68, 68, 0.36)',
    };
  }
  if (isPoisoned) {
    return {
      top: '#6B4514',
      front: '#462C0C',
      side: '#2D1B06',
      stroke: '#FBBF24',
      accent: '#FDE68A',
      led: '#F59E0B',
      glow: 'rgba(245, 158, 11, 0.34)',
    };
  }
  if (isAttacker) {
    return {
      top: '#591D2C',
      front: '#38121C',
      side: '#240A11',
      stroke: isSelected ? '#38BDF8' : '#FB7185',
      accent: '#FDA4AF',
      led: '#F43F5E',
      glow: isSelected ? 'rgba(56, 189, 248, 0.34)' : 'rgba(244, 63, 94, 0.28)',
    };
  }
  if (defended) {
    return {
      top: '#1B5A4B',
      front: '#123D34',
      side: '#0B2721',
      stroke: isSelected ? '#38BDF8' : '#34D399',
      accent: '#6EE7B7',
      led: '#10B981',
      glow: isSelected ? 'rgba(56, 189, 248, 0.34)' : 'rgba(16, 185, 129, 0.28)',
    };
  }
  if (isSelected) {
    return {
      top: '#2A5685',
      front: '#1B3A5E',
      side: '#112640',
      stroke: '#38BDF8',
      accent: '#7DD3FC',
      led: '#38BDF8',
      glow: 'rgba(56, 189, 248, 0.36)',
    };
  }
  return {
    top: '#30476B',
    front: '#1E2F4B',
    side: '#131F34',
    stroke: '#55749E',
    accent: '#7DD3FC',
    led: '#38BDF8',
    glow: 'rgba(2, 6, 23, 0.45)',
  };
}

interface Prism3DProps {
  w: number;
  d: number;
  h: number;
  baseZ?: number;
  offsetX?: number;
  offsetY?: number;
  palette: Palette;
  dashed?: boolean;
  topContent?: React.ReactNode;
  frontContent?: React.ReactNode;
  sideContent?: React.ReactNode;
}

function Prism3D({
  w,
  d,
  h,
  baseZ = 0,
  offsetX = 0,
  offsetY = 0,
  palette,
  dashed = false,
  topContent,
  frontContent,
  sideContent,
}: Prism3DProps) {
  const borderStyle = `${dashed ? '1.25px dashed' : '1.25px solid'} ${palette.stroke}`;

  return (
    <div
      className="preserve-3d absolute left-1/2 top-1/2 pointer-events-none"
      style={{
        width: 0,
        height: 0,
        transform: `translate3d(${offsetX}px, ${offsetY}px, 0px)`,
      }}
    >
      {/* Top face (+Z) */}
      <div
        className="absolute flex items-center justify-center overflow-hidden"
        style={{
          width: w,
          height: d,
          marginLeft: -w / 2,
          marginTop: -d / 2,
          background: `linear-gradient(135deg, ${palette.top} 0%, ${palette.front} 100%)`,
          border: borderStyle,
          borderRadius: 2,
          transform: `translateZ(${baseZ + h}px)`,
          boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.14)',
        }}
      >
        {topContent}
      </div>

      {/* Front-Left bezel face (-X) */}
      <div
        className="absolute flex items-center justify-center overflow-hidden"
        style={{
          width: d,
          height: h,
          marginLeft: -d / 2,
          marginTop: -h / 2,
          background: palette.front,
          border: borderStyle,
          borderRadius: 1,
          transform: `translateX(${-w / 2}px) translateZ(${baseZ + h / 2}px) rotateZ(90deg) rotateX(-90deg)`,
        }}
      >
        {frontContent}
      </div>

      {/* Side-Right face (+Y) */}
      <div
        className="absolute flex items-center justify-center overflow-hidden"
        style={{
          width: w,
          height: h,
          marginLeft: -w / 2,
          marginTop: -h / 2,
          background: palette.side,
          border: borderStyle,
          borderRadius: 1,
          transform: `translateY(${d / 2}px) translateZ(${baseZ + h / 2}px) rotateX(-90deg)`,
        }}
      >
        {sideContent}
      </div>
    </div>
  );
}

interface Cylinder3DProps {
  diameter: number;
  h: number;
  baseZ?: number;
  slices?: number;
  palette: Palette;
  topContent?: React.ReactNode;
  frontLedOffset?: number;
}

function Cylinder3D({
  diameter,
  h,
  baseZ = 0,
  slices = 7,
  palette,
  topContent,
}: Cylinder3DProps) {
  const indices = Array.from({ length: slices }, (_, i) => i);
  return (
    <div className="preserve-3d absolute left-1/2 top-1/2 pointer-events-none" style={{ width: 0, height: 0 }}>
      {indices.map((i) => {
        const z = baseZ + ((i + 1) / slices) * h;
        const isTop = i === slices - 1;
        return (
          <div
            key={i}
            className="absolute flex items-center justify-center"
            style={{
              width: diameter,
              height: diameter,
              marginLeft: -diameter / 2,
              marginTop: -diameter / 2,
              borderRadius: '9999px',
              background: isTop
                ? `radial-gradient(circle at 32% 28%, ${palette.top} 0%, ${palette.front} 100%)`
                : `linear-gradient(135deg, ${palette.front} 10%, ${palette.side} 85%)`,
              border: `1.2px solid ${isTop ? palette.stroke : palette.side}`,
              boxShadow: isTop
                ? `inset 0 1px 0 rgba(255,255,255,0.18), 0 0 0 0.5px ${palette.stroke}`
                : `0 0 0 0.75px ${palette.stroke}55`,
              transform: `translateZ(${z}px)`,
            }}
          >
            {isTop && topContent}
          </div>
        );
      })}
    </div>
  );
}

export function Device3DGraphic({
  role,
  isSelected,
  isAlert,
  isPoisoned,
  defended,
  isAttacker,
  isBypassed = false,
}: Device3DGraphicProps) {
  const p = getHardwarePalette({ isSelected, isAlert, isPoisoned, defended, isAttacker });
  const elevated = isSelected || isAlert || isPoisoned;

  return (
    <div
      className="iso-device-scene relative flex items-center justify-center pointer-events-none"
      style={{ width: 76, height: 60 }}
    >
      <div
        className={`iso-device-rig relative preserve-3d ${elevated ? 'iso-device-rig-active' : ''}`}
        style={{ width: 48, height: 48, opacity: isBypassed ? 0.38 : 1 }}
      >
        {/* Grounded 3D Floor Shadow & Active Pedestal Halo */}
        <div
          className="absolute left-1/2 top-1/2 pointer-events-none"
          style={{
            width: 50,
            height: 44,
            marginLeft: -25,
            marginTop: -22,
            borderRadius: role === 'router' || role === 'database' ? '9999px' : '6px',
            background: '#020617',
            opacity: 0.72,
            filter: 'blur(4px)',
            transform: 'translate3d(-3px, 4px, -2px)',
          }}
        />
        {(isSelected || isAlert || isPoisoned) && (
          <div
            className="absolute left-1/2 top-1/2 pointer-events-none"
            style={{
              width: 56,
              height: 50,
              marginLeft: -28,
              marginTop: -25,
              borderRadius: role === 'router' || role === 'database' ? '9999px' : '8px',
              background: p.glow,
              filter: 'blur(5px)',
              transform: 'translateZ(-1px)',
            }}
          />
        )}

        {/* 1. ROUTER: 3D Stacked Cylindrical Core + Crossed Routing Arrows */}
        {role === 'router' && (
          <>
            <Cylinder3D
              diameter={42}
              h={14}
              slices={8}
              palette={p}
              topContent={
                <svg viewBox="0 0 32 32" className="w-7 h-7" fill="none">
                  <path d="M7 9 L25 23" stroke={p.accent} strokeWidth={2.2} strokeLinecap="round" />
                  <path d="M20 23 L25 23 L24 18" stroke={p.accent} strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
                  <path d="M25 9 L7 23" stroke={p.accent} strokeWidth={2.2} strokeLinecap="round" />
                  <path d="M12 23 L7 23 L8 18" stroke={p.accent} strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              }
            />
            {/* Front link status LEDs */}
            <div
              className="absolute left-1/2 top-1/2 flex items-center gap-1"
              style={{
                width: 14,
                height: 4,
                marginLeft: -7,
                marginTop: -2,
                transform: 'translateX(-21px) translateZ(7px) rotateZ(90deg) rotateX(-90deg)',
              }}
            >
              <span className="w-1.5 h-1.5 rounded-full" style={{ background: p.led }} />
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            </div>
          </>
        )}

        {/* 2. CORE SWITCH: Wide 1U/2U Rack Chassis with Real 3D RJ45 Port Bank */}
        {role === 'switch' && (
          <Prism3D
            w={34}
            d={44}
            h={12}
            palette={p}
            topContent={
              <svg viewBox="0 0 28 32" className="w-6 h-7" fill="none">
                <path d="M6 10 H22" stroke={p.accent} strokeWidth={2} strokeLinecap="round" />
                <path d="M18 7 L22 10 L18 13" stroke={p.accent} strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" />
                <path d="M22 22 H6" stroke={p.accent} strokeWidth={2} strokeLinecap="round" />
                <path d="M10 19 L6 22 L10 25" stroke={p.accent} strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            }
            frontContent={
              <div className="w-full h-full px-1 flex items-center justify-center gap-0.5 bg-[#090F1D]/80">
                {[0, 1, 2, 3, 4, 5, 6].map((idx) => (
                  <div key={idx} className="flex flex-col items-center gap-[1px]">
                    <span
                      className="w-1 h-1 rounded-full"
                      style={{ background: idx % 3 === 0 ? '#FBBF24' : p.led }}
                    />
                    <span className="w-[3.5px] h-[4px] bg-[#1E293B] border border-slate-700/80" />
                  </div>
                ))}
              </div>
            }
            sideContent={
              <div className="w-full h-full flex items-center justify-around px-1">
                <span className="w-4 h-1 rounded-full bg-[#090F1D]" />
                <span className="w-1.5 h-1.5 rounded-full" style={{ background: p.led }} />
              </div>
            }
          />
        )}

        {/* 3. PERIMETER FIREWALL: Tall Armored 3D Inspection Wall + Raised Shield Crest */}
        {role === 'firewall' && (
          <>
            <Prism3D
              w={24}
              d={38}
              h={25}
              palette={p}
              dashed={isBypassed}
              topContent={
                <div className="w-full h-full flex items-center justify-center">
                  <div
                    className="w-7 h-1.5 rounded-full"
                    style={{ background: isBypassed ? '#F59E0B' : p.led, opacity: 0.9 }}
                  />
                </div>
              }
              frontContent={
                <div
                  className="w-full h-full relative flex items-center justify-center"
                  style={{
                    backgroundImage: `
                      linear-gradient(to bottom, transparent 47%, ${p.stroke}55 48%, ${p.stroke}55 52%, transparent 53%),
                      linear-gradient(to right, transparent 47%, ${p.stroke}44 48%, ${p.stroke}44 52%, transparent 53%)
                    `,
                    backgroundSize: '14px 8px',
                  }}
                >
                  <div
                    className="w-4 h-4 flex items-center justify-center rounded-sm border"
                    style={{
                      background: '#090F1D',
                      borderColor: p.accent,
                    }}
                  >
                    <span className="w-1.5 h-1.5 rounded-full" style={{ background: p.led }} />
                  </div>
                </div>
              }
              sideContent={
                <div
                  className="w-full h-full"
                  style={{
                    backgroundImage: `linear-gradient(to bottom, transparent 46%, ${p.stroke}40 48%, ${p.stroke}40 52%, transparent 54%)`,
                    backgroundSize: '100% 8px',
                  }}
                />
              }
            />
          </>
        )}

        {/* 4. SERVER TOWERS: Web Portal, DNS, Mail, NTP, Rogue */}
        {(role === 'webserver' || role === 'dns' || role === 'mail' || role === 'ntp' || role === 'rogue') && (
          <Prism3D
            w={24}
            d={26}
            h={32}
            palette={p}
            topContent={
              <div className="w-4 h-4 flex flex-col justify-between py-0.5">
                <span className="w-full h-[2px] rounded-full bg-[#090F1D]/80" />
                <span className="w-full h-[2px] rounded-full bg-[#090F1D]/80" />
                <span className="w-full h-[2px] rounded-full bg-[#090F1D]/80" />
              </div>
            }
            frontContent={
              <div className="w-full h-full p-1 flex flex-col justify-between bg-[#0B1221]/40">
                <div className="space-y-1">
                  <div className="w-full h-[4px] rounded-[1px] bg-[#090F1D] border border-slate-700/60 flex items-center px-0.5">
                    <span className="w-1 h-1 rounded-full" style={{ background: p.led }} />
                  </div>
                  <div className="w-full h-[4px] rounded-[1px] bg-[#090F1D] border border-slate-700/60 flex items-center px-0.5">
                    <span className="w-1 h-1 rounded-full bg-emerald-400" />
                  </div>
                </div>

                {/* Role-specific front faceplate emblem */}
                <div className="flex items-center justify-center pb-0.5">
                  {role === 'webserver' && (
                    <div className="w-full h-2.5 rounded-[1px] bg-[#090F1D] flex flex-col justify-center gap-[2px] px-1">
                      <span className="w-3/4 h-[1.5px]" style={{ background: p.accent }} />
                      <span className="w-1/2 h-[1.5px] opacity-60" style={{ background: p.accent }} />
                    </div>
                  )}
                  {role === 'dns' && (
                    <svg viewBox="0 0 16 16" className="w-3.5 h-3.5" fill="none">
                      <circle cx="8" cy="8" r="6" stroke={p.accent} strokeWidth="1.4" />
                      <ellipse cx="8" cy="8" rx="2.6" ry="6" stroke={p.accent} strokeWidth="1" />
                      <line x1="2" y1="8" x2="14" y2="8" stroke={p.accent} strokeWidth="1" />
                    </svg>
                  )}
                  {role === 'mail' && (
                    <svg viewBox="0 0 18 12" className="w-4 h-2.5" fill="none">
                      <rect x="1" y="1" width="16" height="10" rx="1.5" fill="#090F1D" stroke={p.accent} strokeWidth="1.2" />
                      <polyline points="1.5,1.5 9,7 16.5,1.5" stroke={p.accent} strokeWidth="1.2" />
                    </svg>
                  )}
                  {role === 'ntp' && (
                    <svg viewBox="0 0 16 16" className="w-3.5 h-3.5" fill="none">
                      <circle cx="8" cy="8" r="6" fill="#090F1D" stroke={p.accent} strokeWidth="1.3" />
                      <polyline points="8,4.2 8,8 11,9.6" stroke={p.accent} strokeWidth="1.4" strokeLinecap="round" />
                    </svg>
                  )}
                  {role === 'rogue' && (
                    <svg viewBox="0 0 16 16" className="w-3.5 h-3.5" fill="none">
                      <polygon points="8,2 14.5,13.5 1.5,13.5" fill="#450A0A" stroke="#F87171" strokeWidth="1.3" />
                      <line x1="8" y1="6" x2="8" y2="9.8" stroke="#FECACA" strokeWidth="1.4" strokeLinecap="round" />
                      <circle cx="8" cy="11.6" r="0.8" fill="#FECACA" />
                    </svg>
                  )}
                </div>
              </div>
            }
            sideContent={
              <div className="w-full h-full flex flex-col justify-end p-1 gap-0.5">
                <span className="w-full h-[1.5px] bg-[#090F1D]/70" />
                <span className="w-full h-[1.5px] bg-[#090F1D]/70" />
                <span className="w-full h-[1.5px] bg-[#090F1D]/70" />
              </div>
            }
          />
        )}

        {/* 5. SQL DATABASE: Three Stacked 3D Platter Cylinders */}
        {role === 'database' && (
          <>
            <Cylinder3D diameter={36} h={7} baseZ={0} slices={5} palette={p} />
            <Cylinder3D diameter={36} h={7} baseZ={9.5} slices={5} palette={p} />
            <Cylinder3D
              diameter={36}
              h={7}
              baseZ={19}
              slices={5}
              palette={p}
              topContent={
                <div className="w-4 h-4 rounded-full border border-dashed flex items-center justify-center" style={{ borderColor: p.accent }}>
                  <span className="w-1.5 h-1.5 rounded-full" style={{ background: p.led }} />
                </div>
              }
            />
          </>
        )}

        {/* 6. WI-FI ACCESS POINT: Low-profile 3D Deck + Dual Standing Dipole Antennas */}
        {role === 'wifi_ap' && (
          <>
            <Prism3D
              w={30}
              d={34}
              h={9}
              palette={p}
              topContent={
                <svg viewBox="0 0 24 24" className="w-5 h-5" fill="none">
                  <path d="M5 10 A 10 10 0 0 1 19 10" stroke={p.accent} strokeWidth={1.8} strokeLinecap="round" />
                  <path d="M8 14 A 6 6 0 0 1 16 14" stroke={p.accent} strokeWidth={1.8} strokeLinecap="round" />
                  <circle cx="12" cy="18" r="1.6" fill={p.led} />
                </svg>
              }
              frontContent={
                <div className="w-full h-full flex items-center justify-center gap-1.5 bg-[#090F1D]/60">
                  <span className="w-1.5 h-1.5 rounded-full" style={{ background: p.led }} />
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                  <span className="w-1.5 h-1.5 rounded-full" style={{ background: p.led }} />
                </div>
              }
            />
            {/* Back-left & back-right 3D dipole antennas */}
            {[-12, 12].map((ay) => (
              <div
                key={ay}
                className="absolute left-1/2 top-1/2 pointer-events-none"
                style={{
                  width: 3,
                  height: 22,
                  marginLeft: -1.5,
                  marginTop: -22,
                  borderRadius: 2,
                  background: `linear-gradient(to top, ${p.front}, ${p.accent})`,
                  border: `0.6px solid ${p.stroke}`,
                  transformOrigin: 'bottom center',
                  transform: `translate3d(11px, ${ay}px, 9px) rotateX(-90deg)`,
                }}
              />
            ))}
          </>
        )}

        {/* 7. CLIENT & ATTACKER WORKSTATIONS: 3D Keyboard Deck + Hinged Tilted Display Lid */}
        {(role === 'client' || role === 'attacker') && (
          <>
            <Prism3D
              w={30}
              d={38}
              h={4.5}
              palette={p}
              topContent={
                <div className="w-full h-full p-1 flex flex-col justify-between items-center">
                  <div className="w-7 h-3 rounded-[1px] bg-[#090F1D]/80 border border-slate-700/50" />
                  <div className="w-3.5 h-1.5 rounded-[1px] bg-[#090F1D]/75" />
                </div>
              }
            />
            {/* Hinged 3D Display Lid along back edge */}
            <div
              className="preserve-3d absolute left-1/2 top-1/2 pointer-events-none"
              style={{
                width: 38,
                height: 24,
                marginLeft: -19,
                marginTop: -24,
                transformOrigin: 'bottom center',
                transform: 'translate3d(14px, 0px, 4.5px) rotateZ(90deg) rotateX(-72deg)',
              }}
            >
              {/* Screen Frame */}
              <div
                className="w-full h-full p-1 flex flex-col justify-center rounded-t-sm"
                style={{
                  background: p.side,
                  border: `1.2px solid ${p.stroke}`,
                  boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.12)',
                }}
              >
                <div
                  className="w-full h-full rounded-[1.5px] bg-[#070D19] p-1 flex flex-col justify-center gap-1"
                  style={{ border: `0.75px solid ${p.accent}66` }}
                >
                  {role === 'attacker' ? (
                    <>
                      <span className="w-4/5 h-[2px] rounded-full bg-rose-400" />
                      <span className="w-full h-[1.5px] rounded-full bg-red-400/80" />
                      <span className="w-3/5 h-[1.5px] rounded-full bg-amber-400/90" />
                    </>
                  ) : (
                    <>
                      <span className="w-full h-[3px] rounded-[1px]" style={{ background: p.top }} />
                      <span className="w-4/5 h-[2px] rounded-full" style={{ background: p.accent }} />
                      <span className="w-2/3 h-[1.5px] rounded-full opacity-55" style={{ background: p.accent }} />
                    </>
                  )}
                </div>
              </div>
            </div>

            {/* External rogue injection antenna for Attacker */}
            {role === 'attacker' && (
              <div
                className="absolute left-1/2 top-1/2 pointer-events-none"
                style={{
                  width: 3,
                  height: 17,
                  marginLeft: -1.5,
                  marginTop: -17,
                  borderRadius: 2,
                  background: 'linear-gradient(to top, #9F1239, #FB7185)',
                  transformOrigin: 'bottom center',
                  transform: 'translate3d(-4px, 21px, 4px) rotateX(-90deg)',
                }}
              />
            )}
          </>
        )}
      </div>
    </div>
  );
}
