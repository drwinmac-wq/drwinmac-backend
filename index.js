// server.js - Velocity Strip-Search Backend
// Trust > Sales - Honest assessments build long-term relationships

import express from 'express';
import cors from 'cors';
import { Resend } from 'resend';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const resend = new Resend(process.env.RESEND_API_KEY);

app.use(cors());
app.use(express.json());

// ========== HONEST ANALYSIS & FLAG DETECTION ==========
// PRIORITY: HARDWARE upgrades (battery, RAM, storage, old systems) THEN security

function analyzeScanResults(data) {
  const flags = [];
  let priorityScore = 0;
  let totalOpportunity = 0;

  // === HARDWARE PRIORITY #1: OLD SYSTEM ===
  // Check for old Intel Macs (2015 and earlier) - HIGHEST PRIORITY
  // For old systems, we detail ALL the aging components
  if (data.macModel && data.cpuBrand) {
    const modelYear = extractYear(data.macModel);
    const isOldIntel = modelYear && modelYear <= 2015;
    
    if (isOldIntel) {
      // MAIN SYSTEM AGE FLAG
      flags.push({
        severity: 'CRITICAL',
        category: 'Hardware Age',
        clientFacing: `${modelYear} Mac - System approaching end of practical life`,
        issue: `System from ${modelYear} - multiple aging components`,
        recommendation: 'Replacement strongly recommended',
        upsell: 'New Mac consultation',
        value: 0
      });
      priorityScore += 4;
      
      // DETAILED COMPONENT FLAGS for old systems
      flags.push({
        severity: 'CRITICAL',
        category: 'Hardware Age',
        clientFacing: `Processor: ${data.cpuBrand?.substring(0, 30) || 'Intel Core'} - ${modelYear} generation CPU lacks modern instruction sets`,
        issue: `CPU from ${modelYear} - no support for modern AI/ML frameworks`,
        recommendation: 'Replacement required for AI workloads',
        upsell: null,
        value: 0
      });
      priorityScore += 2;
      
      flags.push({
        severity: 'CRITICAL',
        category: 'Hardware Age',
        clientFacing: `GPU: Integrated Intel graphics - Insufficient for AI processing`,
        issue: 'Integrated GPU from 2014-2015 generation',
        recommendation: 'External GPU or system replacement',
        upsell: null,
        value: 0
      });
      priorityScore += 2;
      
      // Note about soldered RAM for affected models
      // MacBookPro11 (2014), MacBookPro12 (2015), MacBook8-10 (ALL MacBooks), most MacBookAir
      const hasSolderedRAM = (
        data.macModel.includes('MacBookPro11') ||
        data.macModel.includes('MacBookPro12') ||
        data.macModel.includes('MacBook8') ||
        data.macModel.includes('MacBook9') ||
        data.macModel.includes('MacBook10') ||
        data.macModel.includes('MacBookAir')
      );
      
      if (hasSolderedRAM) {
        flags.push({
          severity: 'CRITICAL',
          category: 'Memory',
          clientFacing: `RAM: ${data.totalRAM}GB (soldered) - Cannot be upgraded on this model`,
          issue: `RAM soldered to logic board - upgrade impossible`,
          recommendation: 'System replacement required for more RAM',
          upsell: 'New Mac consultation',
          value: 0
        });
        priorityScore += 2;
      }
      
    } else if (modelYear && modelYear <= 2017) {
      flags.push({
        severity: 'MODERATE',
        category: 'Hardware Age',
        clientFacing: `${modelYear} Mac - Consider upgrade planning`,
        issue: `System from ${modelYear} - aging hardware`,
        recommendation: 'Plan for replacement within 1-2 years',
        upsell: 'Upgrade consultation',
        value: 0
      });
      priorityScore += 2;
    }
  }

  // === HARDWARE PRIORITY #2: BATTERY ===
  if (data.batteryCapacity && data.batteryCapacity < 100) {
    const capacity = data.batteryCapacity;
    const cycles = data.batteryCycles || 0;
    
    if (capacity < 70 || cycles > 1200) {
      flags.push({
        severity: 'CRITICAL',
        category: 'Battery',
        clientFacing: `Battery: ${cycles} cycles (${capacity}% capacity) - replacement recommended`,
        issue: `Battery Health: ${capacity}% capacity, ${cycles} cycles`,
        recommendation: 'Battery replacement recommended',
        upsell: 'Battery replacement ($249)',
        value: 249
      });
      priorityScore += 3;
      totalOpportunity += 249;
    } else if (capacity < 85 || cycles > 800) {
      flags.push({
        severity: 'MODERATE',
        category: 'Battery',
        clientFacing: `Battery: ${cycles} cycles (${capacity}% capacity) - typical wear for age`,
        issue: `Battery Health: ${capacity}% capacity, ${cycles} cycles`,
        recommendation: 'Battery showing wear - monitor closely',
        upsell: 'Battery replacement ($249)',
        value: 249
      });
      priorityScore += 2;
      totalOpportunity += 249;
    }
  }

  // Backup Check
  if (data.lastBackupDate) {
    const backup = data.lastBackupDate;
    
    // Check if no backup at all
    if (!backup || backup === 'Never' || backup === 'Unknown') {
      flags.push({
        severity: 'CRITICAL',
        category: 'Data Protection',
        clientFacing: 'No backup detected - data at risk',
        issue: 'No backup detected - data at risk',
        recommendation: 'Immediate backup solution required',
        upsell: 'Backup setup service ($149)',
        value: 149
      });
      priorityScore += 3;
      totalOpportunity += 149;
    } else {
      // Check how old the backup is
      const daysOld = calculateDaysSinceBackup(backup);
      
      if (daysOld > 90) {
        // 90+ days = CRITICAL
        flags.push({
          severity: 'CRITICAL',
          category: 'Data Protection',
          clientFacing: `Last backup: ${daysOld} days ago - critically outdated`,
          issue: `Last backup: ${daysOld} days ago`,
          recommendation: 'Re-enable and verify backup system immediately',
          upsell: 'Backup setup service ($149)',
          value: 149
        });
        priorityScore += 3;
        totalOpportunity += 149;
      } else if (daysOld > 30) {
        // 30-90 days = MODERATE
        flags.push({
          severity: 'MODERATE',
          category: 'Data Protection',
          clientFacing: `Last backup: ${daysOld} days ago - needs attention`,
          issue: `Last backup: ${daysOld} days ago`,
          recommendation: 'Verify backup schedule and re-enable if needed',
          upsell: 'Backup setup service ($149)',
          value: 149
        });
        priorityScore += 2;
        totalOpportunity += 149;
      }
      // If < 30 days, backup is good - no flag
    }
  }

  // === SECURITY (LOWER PRIORITY) ===
  // Firewall Check - important but not as critical as hardware
  if (data.firewallEnabled === false) {
    flags.push({
      severity: 'MODERATE',  // Downgraded from CRITICAL
      category: 'Security',
      clientFacing: 'Firewall disabled - security vulnerability',
      issue: 'Firewall is DISABLED',
      recommendation: 'Enable firewall for network protection',
      upsell: 'Security audit ($99)',  // Lower price
      value: 99
    });
    priorityScore += 1;  // Reduced from 2
    totalOpportunity += 99;
  }

  // FileVault Check
  if (data.fileVaultEnabled === false) {
    flags.push({
      severity: 'INFO',  // Downgraded from MODERATE
      category: 'Security',
      clientFacing: 'Disk encryption is OFF',
      issue: 'FileVault (disk encryption) is OFF',
      recommendation: 'Consider enabling FileVault for data protection',
      upsell: 'Security setup ($79)',
      value: 79
    });
    priorityScore += 0;  // No priority bump for this
    totalOpportunity += 79;
  }

  // Storage Check
  if (data.freeStoragePercent !== undefined) {
    const freePercent = data.freeStoragePercent;
    if (freePercent < 10) {
      flags.push({
        severity: 'CRITICAL',
        category: 'Storage',
        clientFacing: `Storage ${freePercent}% available - performance severely degraded`,
        issue: `Storage critically low: ${freePercent}% free`,
        recommendation: 'Immediate storage upgrade or cleanup required',
        upsell: 'Storage upgrade consultation',
        value: 0
      });
      priorityScore += 3;
    } else if (freePercent < 20) {
      flags.push({
        severity: 'MODERATE',
        category: 'Storage',
        clientFacing: `Storage ${freePercent}% available - recommend cleanup`,
        issue: `Storage running low: ${freePercent}% free`,
        recommendation: 'Storage upgrade recommended soon',
        upsell: 'Storage upgrade consultation',
        value: 0
      });
      priorityScore += 2;
    } else if (freePercent >= 50) {
      // Good storage - mention it positively
      flags.push({
        severity: 'POSITIVE',
        category: 'Storage',
        clientFacing: `Storage: ${freePercent}% available - good breathing room`,
        issue: 'Storage healthy',
        recommendation: 'No action needed',
        upsell: null,
        value: 0
      });
    }
  }
  
  // Storage Type Check - HDD vs SSD (HUGE performance opportunity)
  if (data.storageType) {
    const storageType = data.storageType.toUpperCase();
    if (storageType.includes('HDD') || storageType.includes('HARD') || storageType.includes('MECHANICAL')) {
      flags.push({
        severity: 'MODERATE',
        category: 'Storage',
        clientFacing: `Mechanical hard drive (HDD) - SSD upgrade would dramatically improve speed`,
        issue: 'HDD storage - major performance bottleneck',
        recommendation: 'Upgrade to SSD for 5-10x faster performance',
        upsell: 'SSD upgrade ($150-300)',
        value: 200
      });
      priorityScore += 2;
      totalOpportunity += 200;
    }
  }

  // === HARDWARE PRIORITY #3: MEMORY (RAM) ===
  // RAM is critical for performance and AI workloads
  // Skip if already flagged as soldered in old system section
  if (data.totalRAM) {
    const ram = data.totalRAM;
    const pressure = data.memoryPressure || 'Normal';
    const modelYear = extractYear(data.macModel || '');
    
    // Comprehensive soldered RAM detection
    const isSoldered = (
      data.macModel.includes('MacBookPro11') ||
      data.macModel.includes('MacBookPro12') ||
      data.macModel.includes('MacBook8') ||
      data.macModel.includes('MacBook9') ||
      data.macModel.includes('MacBook10') ||
      data.macModel.includes('MacBookAir') ||
      (modelYear && modelYear <= 2015)
    );
    
    if (ram <= 8 && !isSoldered) {
      // Only flag RAM as upgradeable if it's NOT soldered
      flags.push({
        severity: 'CRITICAL',
        category: 'Memory',
        clientFacing: `${ram}GB RAM - insufficient for modern workloads`,
        issue: `Only ${ram}GB RAM - major bottleneck`,
        recommendation: 'RAM upgrade critical for performance',
        upsell: `RAM upgrade ($${ram <= 4 ? '200-400' : '150-300'})`,
        value: ram <= 4 ? 300 : 200
      });
      priorityScore += 3;  // HIGH PRIORITY
      totalOpportunity += (ram <= 4 ? 300 : 200);
    } else if (ram < 16 && (pressure === 'Yellow' || pressure === 'Red' || pressure === 'High') && !isSoldered) {
      flags.push({
        severity: 'MODERATE',
        category: 'Memory',
        clientFacing: `${ram}GB RAM with ${pressure.toLowerCase()} memory pressure`,
        issue: `${ram}GB RAM under pressure`,
        recommendation: 'RAM upgrade recommended for smooth performance',
        upsell: 'RAM upgrade ($150-250)',
        value: 200
      });
      priorityScore += 2;
      totalOpportunity += 200;
    } else if (ram >= 16 && pressure === 'Normal') {
      flags.push({
        severity: 'POSITIVE',
        category: 'Memory',
        clientFacing: `Memory: ${ram}GB - good for most tasks`,
        issue: 'Memory adequate',
        recommendation: 'No action needed',
        upsell: null,
        value: 0
      });
    }
  }

  // Login Items Check
  if (data.loginItemsCount && data.loginItemsCount > 20) {
    flags.push({
      severity: 'MODERATE',
      category: 'Performance',
      clientFacing: `${data.loginItemsCount} apps starting at boot - slowing startup`,
      issue: `${data.loginItemsCount} apps starting at boot`,
      recommendation: 'Performance optimization needed',
      upsell: 'Performance optimization service ($129)',
      value: 129
    });
    priorityScore += 1;
    totalOpportunity += 129;
  }

  // Software Update Check - Service Opportunity
  if (data.softwareUpdateStatus === 'Check manually') {
    flags.push({
      severity: 'MODERATE',
      category: 'Maintenance',
      clientFacing: 'Software updates not configured for automatic installation',
      issue: 'Manual update configuration - likely outdated system',
      recommendation: 'Enable automatic updates and install pending updates',
      upsell: 'System update & optimization service ($149)',
      value: 149
    });
    priorityScore += 1;
    totalOpportunity += 149;
  }

  // Add replacement consultation value for old systems
  const modelYear = extractYear(data.macModel || '');
  if (modelYear && modelYear <= 2015) {
    totalOpportunity += 150;  // Consultation fee for replacement guidance
  }

  // CPU/Architecture Assessment (for AI readiness)
  if (data.architecture && data.cpuBrand) {
    const isIntel = data.architecture.toLowerCase().includes('x86') || data.architecture.toLowerCase().includes('intel');
    const isOldIntel = isIntel && (data.cpuBrand.includes('2015') || data.cpuBrand.includes('2016') || data.cpuBrand.includes('2014'));
    
    if (isOldIntel) {
      flags.push({
        severity: 'CRITICAL',
        category: 'Hardware',
        clientFacing: `Intel CPU (${data.cpuBrand.includes('2015') ? '2015' : 'older'}) - approaching end of software support`,
        issue: 'Old Intel CPU approaching end of life',
        recommendation: 'Replacement recommended for AI workloads',
        upsell: 'Upgrade consultation',
        value: 0
      });
      priorityScore += 2;
    }
  }

  // Software Update Check
  if (data.softwareUpdateStatus && data.softwareUpdateStatus !== 'Up to date' && data.softwareUpdateStatus !== 'Unknown') {
    const updateCount = parseInt(data.softwareUpdateStatus) || 0;
    if (updateCount > 0) {
      flags.push({
        severity: 'MODERATE',
        category: 'Software',
        clientFacing: `${data.softwareUpdateStatus} pending`,
        issue: `${data.softwareUpdateStatus} pending`,
        recommendation: 'Install available updates for security and performance',
        upsell: 'System maintenance service ($129)',
        value: 129
      });
      priorityScore += 1;
      totalOpportunity += 129;
    }
  }

  // WiFi Signal Check
  if (data.wifiSignalStrength && (data.wifiSignalStrength === 'Weak' || data.wifiSignalStrength === 'Fair')) {
    flags.push({
      severity: 'MODERATE',
      category: 'Network',
      clientFacing: `WiFi signal: ${data.wifiSignalStrength} - may impact performance`,
      issue: `WiFi signal strength: ${data.wifiSignalStrength}`,
      recommendation: 'Network optimization or router upgrade recommended',
      upsell: 'Network assessment ($99)',
      value: 99
    });
    priorityScore += 1;
    totalOpportunity += 99;
  }

  // RAM Speed Check (for older Intel Macs) - ONLY if RAM is NOT soldered
  if (data.ramSpeed && data.ramSpeed > 0 && data.ramSpeed < 2400) {
    const isIntel = data.architecture && (data.architecture.toLowerCase().includes('x86') || data.architecture.toLowerCase().includes('intel'));
    const modelYear = extractYear(data.macModel || '');
    
    // Comprehensive soldered RAM detection
    const isSoldered = (
      data.macModel.includes('MacBookPro11') ||
      data.macModel.includes('MacBookPro12') ||
      data.macModel.includes('MacBook8') ||
      data.macModel.includes('MacBook9') ||
      data.macModel.includes('MacBook10') ||
      data.macModel.includes('MacBookAir') ||
      (modelYear && modelYear <= 2015)
    );
    
    // Only flag if Intel AND RAM is NOT soldered (upgradeable)
    if (isIntel && !isSoldered) {
      flags.push({
        severity: 'MODERATE',
        category: 'Performance',
        clientFacing: `RAM speed: ${data.ramSpeed}MHz - slower than modern standards`,
        issue: `RAM Speed: ${data.ramSpeed}MHz (slow)`,
        recommendation: 'RAM upgrade for faster performance',
        upsell: 'RAM upgrade consultation',
        value: 0
      });
      priorityScore += 1;
    }
  }

  // === POSITIVE FLAGS FOR GOOD SYSTEMS ===
  
  // External Monitor Assessment (positive note)
  if (data.externalMonitors && data.externalMonitors > 0) {
    flags.push({
      severity: 'POSITIVE',
      category: 'Display',
      clientFacing: `${data.externalMonitors} external monitor${data.externalMonitors > 1 ? 's' : ''} connected - great for productivity`,
      issue: 'External displays detected',
      recommendation: 'Current setup is productivity-optimized',
      upsell: null,
      value: 0
    });
  }
  
  // High RAM (32GB+) - Positive
  if (data.totalRAM && data.totalRAM >= 32) {
    flags.push({
      severity: 'POSITIVE',
      category: 'Memory',
      clientFacing: `${data.totalRAM}GB RAM - excellent for multitasking and professional workflows`,
      issue: 'High RAM capacity',
      recommendation: 'System well-equipped for demanding tasks',
      upsell: null,
      value: 0
    });
  }
  
  // M-series chip detection - Positive
  if (data.cpuBrand && (data.cpuBrand.includes('M1') || data.cpuBrand.includes('M2') || data.cpuBrand.includes('M3') || data.cpuBrand.includes('M4'))) {
    flags.push({
      severity: 'POSITIVE',
      category: 'Hardware Age',
      clientFacing: `${data.cpuBrand.substring(0, 20)} - Modern Apple Silicon processor with excellent performance and efficiency`,
      issue: 'Modern Apple Silicon',
      recommendation: 'System is current-generation hardware',
      upsell: null,
      value: 0
    });
  }
  
  // Recent backup - Positive
  if (data.lastBackupDate && data.lastBackupDate !== 'Never' && data.lastBackupDate !== 'Unknown') {
    const daysOld = calculateDaysSinceBackup(data.lastBackupDate);
    if (daysOld <= 7) {
      flags.push({
        severity: 'POSITIVE',
        category: 'Data Protection',
        clientFacing: `Recent backup (${daysOld === 0 ? 'today' : daysOld + ' days ago'}) - data well protected`,
        issue: 'Regular backups active',
        recommendation: 'Continue current backup schedule',
        upsell: null,
        value: 0
      });
    }
  }
  
  // Excellent battery health - Positive
  if (data.batteryCapacity && data.batteryCapacity >= 90 && data.batteryCycles && data.batteryCycles < 500) {
    flags.push({
      severity: 'POSITIVE',
      category: 'Battery',
      clientFacing: `Battery: ${data.batteryCapacity}% capacity with ${data.batteryCycles} cycles - excellent health`,
      issue: 'Battery in excellent condition',
      recommendation: 'No action needed',
      upsell: null,
      value: 0
    });
  }

  // External Monitor Assessment (kept for backwards compatibility)
  if (data.externalMonitors && data.externalMonitors > 0) {
    flags.push({
      severity: 'POSITIVE',
      category: 'Display',
      clientFacing: `Using ${data.externalMonitors} external monitor${data.externalMonitors > 1 ? 's' : ''} - good productivity setup`,
      issue: 'External monitors detected',
      recommendation: 'No action needed',
      upsell: null,
      value: 0
    });
  }

  // Calculate priority level and system health
  const criticalCount = flags.filter(f => f.severity === 'CRITICAL').length;
  const moderateCount = flags.filter(f => f.severity === 'MODERATE').length;
  const positiveCount = flags.filter(f => f.severity === 'POSITIVE').length;
  
  let priorityLevel = 'COLD';
  let systemHealth = 'GOOD';
  
  if (criticalCount >= 3 || priorityScore >= 8) {
    priorityLevel = 'HOT';
    systemHealth = 'CRITICAL';
  } else if (criticalCount >= 2 || priorityScore >= 6) {
    priorityLevel = 'WARM';
    systemHealth = 'NEEDS_ATTENTION';
  } else if (criticalCount >= 1 || priorityScore >= 4) {
    priorityLevel = 'WARM';
    systemHealth = 'MODERATE';
  } else if (positiveCount >= 2 && moderateCount <= 1) {
    systemHealth = 'EXCELLENT';
  }

  return {
    flags,
    priorityScore,
    priorityLevel,
    systemHealth,
    criticalCount,
    moderateCount,
    positiveCount,
    totalOpportunity,
    flagCount: flags.length
  };
}

function calculateDaysSinceBackup(backupDate) {
  try {
    const backup = new Date(backupDate);
    const now = new Date();
    const diffTime = Math.abs(now - backup);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    return diffDays;
  } catch {
    return 0;
  }
}

function extractYear(macModel) {
  if (!macModel) return null;
  
  // First try: Look for explicit year in model string (e.g., "2014 MacBook Pro")
  const yearMatch = macModel.match(/20\d{2}/);
  if (yearMatch) {
    return parseInt(yearMatch[0]);
  }
  
  // Second try: Comprehensive model number → year mapping
  // Format: MacBookPro11,3 → Number after model name is the key
  
  // MacBook Pro models
  if (macModel.includes('MacBookPro18')) return 2021; // M1 Pro/Max
  if (macModel.includes('MacBookPro17')) return 2020; // M1
  if (macModel.includes('MacBookPro16')) return 2019;
  if (macModel.includes('MacBookPro15')) return 2018;
  if (macModel.includes('MacBookPro14')) return 2017;
  if (macModel.includes('MacBookPro13')) return 2016;
  if (macModel.includes('MacBookPro12')) return 2015;
  if (macModel.includes('MacBookPro11')) return 2014; // Your system
  if (macModel.includes('MacBookPro10')) return 2013;
  if (macModel.includes('MacBookPro9')) return 2012;
  if (macModel.includes('MacBookPro8')) return 2011;
  
  // MacBook Air models
  if (macModel.includes('MacBookAir10')) return 2020; // M1
  if (macModel.includes('MacBookAir9')) return 2020;
  if (macModel.includes('MacBookAir8')) return 2018;
  if (macModel.includes('MacBookAir7')) return 2015;
  if (macModel.includes('MacBookAir6')) return 2013;
  if (macModel.includes('MacBookAir5')) return 2012;
  
  // MacBook (12-inch, discontinued)
  if (macModel.includes('MacBook10')) return 2017;
  if (macModel.includes('MacBook9')) return 2016;
  if (macModel.includes('MacBook8')) return 2015; // Bug #1 fix
  
  // iMac models
  if (macModel.includes('iMac21')) return 2021; // M1
  if (macModel.includes('iMac20')) return 2020;
  if (macModel.includes('iMac19')) return 2019;
  if (macModel.includes('iMac18')) return 2017;
  if (macModel.includes('iMac17')) return 2015;
  if (macModel.includes('iMac16')) return 2015;
  if (macModel.includes('iMac15')) return 2014;
  if (macModel.includes('iMac14')) return 2013;
  if (macModel.includes('iMac13')) return 2012;
  
  // Mac mini models
  if (macModel.includes('Macmini9')) return 2020; // M1
  if (macModel.includes('Macmini8')) return 2018;
  if (macModel.includes('Macmini7')) return 2014;
  if (macModel.includes('Macmini6')) return 2012;
  
  // Mac Pro models
  if (macModel.includes('MacPro7')) return 2019;
  if (macModel.includes('MacPro6')) return 2013;
  
  // Mac Studio
  if (macModel.includes('MacStudio')) return 2022; // M1 Max/Ultra
  
  // If no match found, return null
  return null;
}

// ========== HONEST TIMELINE GENERATION ==========

function generateTimeline(analysis, data) {
  const { systemHealth, criticalCount } = analysis;
  
  switch (systemHealth) {
    case 'EXCELLENT':
      return {
        assessment: 'Your Mac is in excellent shape and should serve you well for 2-3+ years.',
        proTip: 'Regular maintenance (battery calibration, storage optimization, security updates) can extend your Mac\'s productive life even further. We offer quarterly tune-ups to keep you ahead of issues - reply if you\'d like details.'
      };
      
    case 'GOOD':
      return {
        assessment: 'Your Mac is in good condition and should serve you well for 1-2+ years with attention to the items noted above.',
        proTip: 'Regular maintenance can extend your system\'s lifespan and prevent small issues from becoming expensive problems. We offer quarterly check-ups - reply to learn more.'
      };
      
    case 'MODERATE':
      return {
        assessment: 'Address the noted items within 2-3 months to prevent workflow disruption.',
        proTip: 'Acting now preserves your options and avoids emergency situations. We can help you prioritize which fixes deliver the most value first - reply to discuss your best path forward.'
      };
      
    case 'NEEDS_ATTENTION':
      return {
        assessment: 'Address the critical items within 4-6 weeks to maintain productivity.',
        proTip: 'These issues will worsen over time. We can help you create a cost-effective action plan that addresses the most urgent items first - reply to explore your options.'
      };
      
    case 'CRITICAL':
      return {
        assessment: 'Immediate attention recommended. Plan upgrade or replacement within 4-6 weeks.',
        proTip: 'Waiting risks data loss and forced last-minute decisions. We can help you evaluate whether targeted upgrades or replacement makes more sense for your situation - reply to explore your options.'
      };
      
    default:
      return {
        assessment: 'Your system assessment is complete.',
        proTip: 'We\'re here if you have questions about optimizing your Mac\'s performance.'
      };
  }
}

// ========== HELPER FUNCTIONS FOR CLIENT EMAIL ==========

function getUrgencyTimeline(flag) {
  if (flag.severity === 'CRITICAL') {
    if (flag.category === 'Hardware Age') return 'Replace within 3-6 months';
    if (flag.category === 'Battery') return 'Address within 2-4 weeks';
    // Check if it's soldered RAM - don't suggest upgrade, suggest replacement
    if (flag.category === 'Memory') {
      if (flag.clientFacing.includes('soldered') || flag.clientFacing.includes('Cannot be upgraded')) {
        return 'System replacement needed for more RAM';
      }
      return 'Upgrade within 1-2 months';
    }
    if (flag.category === 'Storage') return 'Address within 1-2 weeks';
    if (flag.category === 'Data Protection') return 'Set up immediately';
    return 'Address within 2-4 weeks';
  }
  if (flag.severity === 'MODERATE') {
    if (flag.category === 'Battery') return 'Plan replacement within 6-12 months';
    if (flag.category === 'Memory') return 'Consider upgrade within 3-6 months';
    if (flag.category === 'Storage') return 'Clean up or upgrade within 1-2 months';
    if (flag.category === 'Security') return 'Enable within 1 month';
    if (flag.category === 'Maintenance') return 'Address within 2-4 weeks';
    return 'Address within 2-3 months';
  }
  return '';
}

function getConsequence(flag) {
  // Add real-world consequences for service issues
  if (flag.clientFacing.includes('No backup') || flag.clientFacing.includes('backup')) {
    return 'If your drive fails, you lose everything';
  }
  if (flag.clientFacing.includes('encryption') || flag.clientFacing.includes('FileVault')) {
    return 'If laptop is lost/stolen, your files are readable';
  }
  if (flag.clientFacing.includes('Firewall')) {
    return 'Vulnerable to network attacks';
  }
  if (flag.clientFacing.includes('Software updates') || flag.clientFacing.includes('updates')) {
    return 'Missing critical security patches';
  }
  if (flag.clientFacing.includes('Login items') || flag.clientFacing.includes('startup')) {
    return 'Wasting 2-5 minutes every boot';
  }
  return '';
}

function calculateSystemGrade(analysis, data) {
  const { priorityScore, criticalCount, moderateCount } = analysis;
  const { totalRAM } = data;
  
  let grade = 'B';
  let color = '#4caf50';
  let proTip = 'Your system is performing well. Regular maintenance will keep it running smoothly.';
  
  // Grading logic with HONEST, GROUNDED pro tips
  if (priorityScore >= 12 || criticalCount >= 4) {
    grade = 'D-';
    color = '#c62828';
    proTip = 'Your Mac has reached the point where replacement makes more financial sense than continued repairs. Modern software requirements are outpacing what this hardware can deliver.';
  } else if (priorityScore >= 10 || criticalCount >= 3) {
    grade = 'D+';
    color = '#d32f2f';
    proTip = 'This system is nearing the end of its practical lifespan. Budget for replacement within 3-6 months to avoid being forced into a last-minute decision.';
  } else if (priorityScore >= 7 || criticalCount >= 2) {
    grade = 'C-';
    color = '#f57c00';
    proTip = 'Multiple hardware limitations are affecting your productivity. Address the critical items first, but start planning for eventual replacement.';
  } else if (priorityScore >= 5 || criticalCount >= 1) {
    grade = 'C+';
    color = '#ffa726';
    proTip = 'Your system will continue working for everyday tasks, but upgrading or replacing within 6-12 months will prevent workflow disruptions.';
  } else if (priorityScore >= 3 || moderateCount >= 2) {
    grade = 'B-';
    color = '#66bb6a';
    proTip = 'A few minor improvements will extend your system\'s useful life. Addressing these proactively is cheaper than waiting for problems.';
  } else if (priorityScore >= 1) {
    grade = 'B+';
    color = '#43a047';
    proTip = 'Solid system overall. Regular backups and maintenance will keep you running smoothly for years.';
  } else if (totalRAM >= 16) {
    grade = 'A';
    color = '#2e7d32';
    proTip = 'Excellent hardware configuration. Focus on data protection and you\'re set for the long haul.';
  }
  
  // A+ reserved for near-perfect systems
  if (priorityScore === 0 && criticalCount === 0 && moderateCount === 0 && totalRAM >= 32) {
    grade = 'A+';
    color = '#1b5e20';
    proTip = 'Outstanding system with professional-grade specs. Maintain your current backup and security practices.';
  }
  
  return { letter: grade, color, proTip };
}

// ========== CLIENT EMAIL GENERATION ==========

function generateClientEmail(data, analysis) {
  const { clientName, clientEmail, macModel, totalRAM, storageType, cpuBrand, totalStorage, freeStoragePercent } = data;
  const { flags, systemHealth, criticalCount, moderateCount } = analysis;

  // Separate ALL hardware and service issues - NO CAPS
  const hardwareIssues = flags.filter(f => 
    (f.severity === 'CRITICAL' || f.severity === 'MODERATE') && 
    (f.category === 'Hardware Age' || f.category === 'Memory' || f.category === 'Battery' || f.category === 'Storage')
  );
  
  const serviceIssues = flags.filter(f => 
    f.category === 'Data Protection' || f.category === 'Security' || f.category === 'Performance' || f.category === 'Maintenance'
  );
  
  // Separate by severity for priority tiers
  const criticalHardware = hardwareIssues.filter(f => f.severity === 'CRITICAL');
  const moderateHardware = hardwareIssues.filter(f => f.severity === 'MODERATE');
  const criticalServices = serviceIssues.filter(f => f.severity === 'CRITICAL');
  const moderateServices = serviceIssues.filter(f => f.severity === 'MODERATE');

  // Build hardware issues list - ORGANIZED BY PRIORITY
  let hardwareList = '';
  if (hardwareIssues.length > 0) {
    if (criticalHardware.length > 0) {
      hardwareList += `<p style="margin: 15px 0 5px 0; font-weight: bold; color: #d32f2f;">🔴 CRITICAL - Needs Attention Now (${criticalHardware.length}):</p><ul style="margin: 5px 0; padding-left: 20px;">`;
      criticalHardware.forEach((flag) => {
        const urgency = getUrgencyTimeline(flag);
        hardwareList += `<li style="margin: 8px 0;"><strong>${flag.clientFacing}</strong>${urgency ? `<br><span style="color: #666; font-size: 14px;">⏱ Timeline: ${urgency}</span>` : ''}</li>`;
      });
      hardwareList += `</ul>`;
    }
    
    if (moderateHardware.length > 0) {
      hardwareList += `<p style="margin: 15px 0 5px 0; font-weight: bold; color: #f57c00;">🟡 MODERATE - Plan Ahead (${moderateHardware.length}):</p><ul style="margin: 5px 0; padding-left: 20px;">`;
      moderateHardware.forEach((flag) => {
        const urgency = getUrgencyTimeline(flag);
        hardwareList += `<li style="margin: 8px 0;"><strong>${flag.clientFacing}</strong>${urgency ? `<br><span style="color: #666; font-size: 14px;">⏱ Timeline: ${urgency}</span>` : ''}</li>`;
      });
      hardwareList += `</ul>`;
    }
  } else {
    hardwareList = '<p style="color: #4caf50;">✅ No critical hardware issues detected</p>';
  }

  // Build service issues list - ORGANIZED BY PRIORITY
  let serviceList = '';
  if (serviceIssues.length > 0) {
    if (criticalServices.length > 0) {
      serviceList += `<p style="margin: 15px 0 5px 0; font-weight: bold; color: #d32f2f;">🔴 CRITICAL - Address Immediately (${criticalServices.length}):</p><ul style="margin: 5px 0; padding-left: 20px;">`;
      criticalServices.forEach((flag) => {
        const urgency = getUrgencyTimeline(flag);
        const consequence = getConsequence(flag);
        serviceList += `<li style="margin: 8px 0;"><strong>${flag.clientFacing}</strong>${consequence ? `<br><span style="color: #c62828; font-size: 13px;">⚠️ Risk: ${consequence}</span>` : ''}${urgency ? `<br><span style="color: #666; font-size: 14px;">⏱ Timeline: ${urgency}</span>` : ''}</li>`;
      });
      serviceList += `</ul>`;
    }
    
    if (moderateServices.length > 0) {
      serviceList += `<p style="margin: 15px 0 5px 0; font-weight: bold; color: #f57c00;">🟡 MODERATE - Recommended (${moderateServices.length}):</p><ul style="margin: 5px 0; padding-left: 20px;">`;
      moderateServices.forEach((flag) => {
        const urgency = getUrgencyTimeline(flag);
        const consequence = getConsequence(flag);
        serviceList += `<li style="margin: 8px 0;"><strong>${flag.clientFacing}</strong>${consequence ? `<br><span style="color: #e65100; font-size: 13px;">⚠️ Risk: ${consequence}</span>` : ''}${urgency ? `<br><span style="color: #666; font-size: 14px;">⏱ Timeline: ${urgency}</span>` : ''}</li>`;
      });
      serviceList += `</ul>`;
    }
  } else {
    serviceList = '<p style="color: #4caf50;">✅ System maintenance up to date</p>';
  }

  // Calculate overall grade
  const grade = calculateSystemGrade(analysis, data);

  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
  
  <div style="text-align: center; padding: 20px 0; border-bottom: 2px solid #5b7db1;">
    <h1 style="color: #5b7db1; margin: 0;">Velocity Strip-Search</h1>
    <p style="color: #666; margin: 5px 0 0 0;">Hardware Analysis Report</p>
  </div>

  <div style="padding: 30px 0;">
    <p>${clientName ? `Hi ${clientName.charAt(0).toUpperCase() + clientName.slice(1)},` : 'Hello,'}</p>
    <p>Your comprehensive hardware scan is complete. Here's what we found:</p>

    <div style="background: #f8f9fa; border-radius: 8px; padding: 20px; margin: 20px 0;">
      <h3 style="margin-top: 0; color: #5b7db1;">Quick Summary</h3>
      <table style="width: 100%; border-collapse: collapse;">
        <tr>
          <td style="padding: 8px 0;"><strong>Mac Model:</strong></td>
          <td style="padding: 8px 0;">${macModel || 'Unknown'}</td>
        </tr>
        <tr>
          <td style="padding: 8px 0;"><strong>Processor:</strong></td>
          <td style="padding: 8px 0;">${cpuBrand || 'Unknown'}</td>
        </tr>
        <tr>
          <td style="padding: 8px 0;"><strong>Memory (RAM):</strong></td>
          <td style="padding: 8px 0;">${totalRAM || 0} GB</td>
        </tr>
        <tr>
          <td style="padding: 8px 0;"><strong>Storage:</strong></td>
          <td style="padding: 8px 0;">${totalStorage || 0} GB ${storageType || ''} (${freeStoragePercent || 0}% free)</td>
        </tr>
        <tr>
          <td style="padding: 8px 0;"><strong>Overall AI Preparedness Grade:</strong></td>
          <td style="padding: 8px 0; font-size: 18px;"><strong style="color: ${grade.color};">${grade.letter}</strong></td>
        </tr>
      </table>
      
      <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #ddd;">
        <h4 style="margin: 0 0 10px 0; color: #5b7db1; font-size: 14px;">Key Health Metrics:</h4>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 13px;">
          <div><strong>Battery:</strong> ${data.batteryCapacity || 0}% (${data.batteryCycles || 0} cycles)</div>
          <div><strong>Last Backup:</strong> ${data.lastBackupDate ? new Date(data.lastBackupDate).toLocaleDateString() : 'Never'}</div>
          <div><strong>Firewall:</strong> ${data.firewallEnabled ? 'ON' : 'OFF'}</div>
          <div><strong>Disk Encryption:</strong> ${data.fileVaultEnabled ? 'ON' : 'OFF'}</div>
          <div><strong>Software Updates:</strong> ${data.softwareUpdateStatus === 'Check manually' ? 'Updates needed' : data.softwareUpdateStatus || 'Unknown'}</div>
          <div><strong>Memory Pressure:</strong> ${data.memoryPressure || 'Unknown'}</div>
        </div>
      </div>
    </div>

    <div style="background: #fff3cd; border-left: 4px solid #cc6600; padding: 20px; margin: 20px 0;">
      <h3 style="margin-top: 0; color: #cc6600;">⚠️ Complete Hardware Diagnostic</h3>
      <p style="margin: 0 0 15px 0; color: #666; font-size: 14px;">This is your full hardware report - everything we found, organized by urgency. When we talk, I'll help you prioritize which items to tackle first based on your budget and timeline.</p>
      ${hardwareList}
    </div>

    <div style="background: #e8f4f8; border-radius: 8px; padding: 20px; margin: 20px 0;">
      <h3 style="margin-top: 0; color: #5b7db1;">System Maintenance & Security</h3>
      <p style="margin: 0 0 15px 0; color: #666; font-size: 14px;">These are software-side items that can be addressed relatively quickly. Each includes the real-world risk if left unaddressed.</p>
      ${serviceList}
    </div>

    <div style="background: #f0f0f0; border-radius: 8px; padding: 15px; margin: 20px 0;">
      <p style="margin: 0;"><strong>Pro tip:</strong> ${grade.proTip}</p>
    </div>

    <div style="background: #fff8e1; border-left: 4px solid #f57c00; padding: 20px; margin: 20px 0;">
      <h3 style="margin-top: 0; color: #f57c00;">📌 What This Means For Your Day-to-Day</h3>
      <p style="margin: 10px 0;">Based on your ${data.platform === 'windows' ? 'PC' : 'Mac'}'s hardware age and limitations, here's what you're experiencing (or will soon):</p>
      <ul style="margin: 10px 0; padding-left: 20px;">
        <li><strong>Slower performance</strong> - Your ${data.cpuBrand ? data.cpuBrand.substring(0, 40) : 'processor'} and ${data.totalRAM}GB RAM can't keep up with modern software demands</li>
        <li><strong>Software compatibility issues</strong> - Many apps now require newer processors and more memory than your system can provide</li>
        ${data.batteryCapacity && data.batteryCapacity < 85 ? `<li><strong>Short battery life</strong> - At ${data.batteryCycles || 0} cycles and ${data.batteryCapacity}% capacity, runtime is significantly reduced</li>` : ''}
        ${data.batteryCycles && data.batteryCycles > 800 && (!data.batteryCapacity || data.batteryCapacity >= 85) ? `<li><strong>Battery aging</strong> - At ${data.batteryCycles} cycles, battery may degrade rapidly in the coming months</li>` : ''}
        ${hardwareIssues.some(f => f.clientFacing.includes('soldered')) ? '<li><strong>Limited upgrade path</strong> - With soldered components and aging hardware, there\'s no way to extend this system\'s life through upgrades</li>' : ''}
        <li><strong>Resale value declining fast</strong> - Systems this old typically hit the "recycle vs resell" threshold around 10-12 years</li>
      </ul>
      <p style="margin: 10px 0;"><strong>The good news?</strong> You're catching this before an emergency forces your hand. That gives you time to plan.</p>
    </div>

    <div style="background: #e3f2fd; border: 2px solid #5b7db1; border-radius: 8px; padding: 25px; margin: 30px 0;">
      <h3 style="margin-top: 0; color: #5b7db1;">📞 What Happens Next</h3>
      <p style="margin: 10px 0;">This scan identified ${criticalCount} critical hardware issue${criticalCount === 1 ? '' : 's'} and ${moderateCount} optimization opportunit${moderateCount === 1 ? 'y' : 'ies'}. The diagnostic is complete - now let's discuss your options.</p>
      
      <p style="margin: 15px 0;"><strong>In a quick 15-minute call, I'll help you:</strong></p>
      <ol style="margin: 10px 0; padding-left: 20px;">
        <li style="margin: 8px 0;"><strong>Understand your timeline</strong> - Based on your system's age and condition, when do you realistically need to make a move?</li>
        <li style="margin: 8px 0;"><strong>Evaluate your options</strong> - New ${data.platform === 'windows' ? 'PC' : 'Mac'}? Refurbished? Targeted repairs? What makes sense for your budget and workflow?</li>
        <li style="margin: 8px 0;"><strong>Plan your transition</strong> - If replacement is the answer, how do you migrate data, what specs do you actually need, and when should you pull the trigger?</li>
        <li style="margin: 8px 0;"><strong>Avoid costly mistakes</strong> - Most people overspend on specs they don't need, or wait too long and lose data. Let's avoid both.</li>
      </ol>

      <div style="text-align: center; margin: 25px 0;">
        <a href="https://calendly.com/drwinmac" style="display: inline-block; background: #5b7db1; color: white; padding: 15px 40px; text-decoration: none; border-radius: 6px; font-weight: bold; font-size: 16px;">📅 BOOK YOUR 15-MINUTE STRATEGY CALL</a>
      </div>

      <p style="margin: 15px 0; padding: 15px; background: #fff3cd; border-left: 4px solid #ffc107; font-size: 14px;"><strong>⏰ Limited Availability:</strong> I work solo (by choice), so I limit consultations to 3 per week to give each client proper attention.</p>

      <p style="margin: 10px 0;">Based on your system's condition and the timeline flags above, you have roughly <strong>3-6 months</strong> before decisions start getting forced on you. Book now while you have time to plan.</p>
      
      <p style="margin: 10px 0; font-size: 13px; color: #666;">Not ready yet? That's fine - just know that waiting too long usually costs more (emergency purchases, lost data, rushed decisions).</p>
    </div>

    <div style="background: #f5f5f5; border-radius: 8px; padding: 20px; margin: 20px 0;">
      <h3 style="margin-top: 0; color: #333;">Why Dr.WinMac?</h3>
      <p style="margin: 10px 0;">I've been working with PCs and Macs since 1999 - started during the Y2K transition helping businesses navigate hardware upgrades and system migrations. 25+ years across both platforms.</p>
      <p style="margin: 10px 0;">My focus is simple: <strong>hardware diagnostics, upgrade planning, and helping you avoid expensive mistakes.</strong> I don't sell computers, don't get vendor commissions, and I don't push services you don't need.</p>
      <p style="margin: 10px 0;">Whether you're running Windows or macOS, this scan gives you the full picture before making any decisions.</p>
      <p style="margin: 15px 0 5px 0;">- Jeremy<br>
      Dr.WinMac<br>
      <a href="mailto:Jeremy@drwinmac.tech" style="color: #5b7db1;">Jeremy@drwinmac.tech</a></p>
    </div>

    <p style="font-size: 13px; color: #666; margin-top: 30px;">Questions about your results? Just reply to this email.</p>
  </div>

  <div style="border-top: 2px solid #eee; padding-top: 20px; margin-top: 30px; text-align: center; color: #999; font-size: 12px;">
    <p>© 2026 Dr.WinMac. All rights reserved.</p>
    <p><a href="https://www.drwinmac.tech" style="color: #5b7db1;">www.drwinmac.tech</a></p>
  </div>

</body>
</html>
  `;

  return html;
}

// ========== INTERNAL EMAIL (unchanged from before) ==========

function generateInternalEmail(data, analysis) {
  const { clientName, clientEmail } = data;
  const { flags, priorityScore, priorityLevel, criticalCount, moderateCount, totalOpportunity, systemHealth } = analysis;

  const criticalFlags = flags.filter(f => f.severity === 'CRITICAL');
  const moderateFlags = flags.filter(f => f.severity === 'MODERATE');

  let flagsList = '';
  
  if (criticalFlags.length > 0) {
    flagsList += '<h3 style="color: #d32f2f;">⚠️ CRITICAL FLAGS (' + criticalFlags.length + '):</h3><ul>';
    criticalFlags.forEach(flag => {
      flagsList += `<li><strong>${flag.category}:</strong> ${flag.issue}`;
      if (flag.upsell) flagsList += ` → <strong>${flag.upsell}</strong>`;
      flagsList += `</li>`;
    });
    flagsList += '</ul>';
  }

  if (moderateFlags.length > 0) {
    flagsList += '<h3 style="color: #f57c00;">⚡ MODERATE FLAGS (' + moderateFlags.length + '):</h3><ul>';
    moderateFlags.forEach(flag => {
      flagsList += `<li><strong>${flag.category}:</strong> ${flag.issue}`;
      if (flag.upsell) flagsList += ` → <strong>${flag.upsell}</strong>`;
      flagsList += `</li>`;
    });
    flagsList += '</ul>';
  }

  let callScriptHook = 'Your scan results look great overall';
  if (criticalFlags.length > 0) {
    const topFlag = criticalFlags[0];
    callScriptHook = `I noticed ${topFlag.issue.toLowerCase()}. ${topFlag.recommendation}. Have you experienced any issues related to this?`;
  } else if (moderateFlags.length > 0) {
    const topFlag = moderateFlags[0];
    callScriptHook = `I saw ${topFlag.issue.toLowerCase()}. This is something we can help optimize. Have you noticed any performance concerns?`;
  }

  const timeline = generateTimeline(analysis, data);

  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: 'Courier New', monospace; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 20px; background: #f5f5f5;">
  
  <div style="background: #fff; border: 2px solid #5b7db1; border-radius: 8px; padding: 20px; margin-bottom: 20px;">
    <h1 style="margin: 0; color: #5b7db1;">🎯 NEW LEAD CAPTURED</h1>
    <p style="font-size: 18px; margin: 10px 0;"><strong>${clientName || 'Name not provided'}</strong></p>
    <p style="font-size: 18px; margin: 10px 0;"><strong>${clientEmail}</strong></p>
    <p style="margin: 5px 0;">Scan Date: ${new Date().toLocaleString()}</p>
    <p style="margin: 5px 0;">Mac: ${data.macModel || 'Unknown'} | Tier: ${data.aiPreparednessTier || 'Unknown'}</p>
    <p style="margin: 5px 0;">System Health: <strong>${systemHealth}</strong></p>
  </div>

  <div style="background: ${priorityLevel === 'HOT' ? '#d32f2f' : priorityLevel === 'WARM' ? '#f57c00' : '#666'}; color: white; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
    <h2 style="margin: 0;">🚨 PRIORITY: ${priorityScore}/10 (${priorityLevel}${priorityLevel === 'HOT' ? ' - Route to Jeremy' : ''})</h2>
  </div>

  <div style="background: #fff; border-radius: 8px; padding: 20px; margin-bottom: 20px;">
    ${flagsList || '<p>No critical issues detected - system in good health.</p>'}
    
    ${totalOpportunity > 0 ? `
    <div style="background: #e8f5e9; border-left: 4px solid #4caf50; padding: 15px; margin-top: 20px;">
      <h3 style="margin: 0 0 10px 0; color: #2e7d32;">💰 TOTAL SERVICE OPPORTUNITY: $${totalOpportunity}+</h3>
    </div>
    ` : ''}
    
    <div style="background: #e3f2fd; border-left: 4px solid #2196f3; padding: 15px; margin-top: 20px;">
      <h4 style="margin: 0 0 5px 0;">TIMELINE GIVEN TO CLIENT:</h4>
      <p style="margin: 5px 0;">${timeline.assessment}</p>
      <p style="margin: 5px 0; font-style: italic;">"Pro tip: ${timeline.proTip}"</p>
    </div>
  </div>

  <div style="background: #d4edda; border: 3px solid #28a745; border-radius: 8px; padding: 25px; margin-bottom: 20px;">
    <h2 style="margin-top: 0; color: #155724;">🎯 PRIORITY ACTION GUIDE - YOUR CALL CHEAT SHEET</h2>
    <p style="margin: 10px 0; font-size: 15px;"><strong>When they call overwhelmed, scroll to this section and say:</strong></p>
    <p style="margin: 10px 0; padding: 15px; background: #fff; border-left: 4px solid #28a745; font-style: italic;">"I know that's a lot to take in. Let me break down what actually needs attention RIGHT NOW vs. what can wait..."</p>
    
    <h3 style="color: #155724; margin-top: 20px;">IMMEDIATE PRIORITIES (Next 2-4 Weeks):</h3>
    <ul style="margin: 10px 0;">
      ${criticalFlags.slice(0, 3).map(f => `<li style="margin: 8px 0;"><strong>${f.issue}</strong> - ${f.recommendation}</li>`).join('')}
    </ul>
    
    ${criticalCount > 3 ? `<p style="margin: 10px 0; color: #666;"><em>+ ${criticalCount - 3} more critical items (see full list below)</em></p>` : ''}
    
    <h3 style="color: #856404; margin-top: 20px;">CAN WAIT (Next 1-3 Months):</h3>
    <ul style="margin: 10px 0;">
      ${moderateFlags.slice(0, 3).map(f => `<li style="margin: 8px 0;">${f.issue} - ${f.recommendation}</li>`).join('')}
    </ul>
    
    ${moderateCount > 3 ? `<p style="margin: 10px 0; color: #666;"><em>+ ${moderateCount - 3} more moderate items</em></p>` : ''}
    
    <div style="background: #fff; padding: 15px; margin-top: 20px; border-left: 4px solid #007bff;">
      <h4 style="margin-top: 0; color: #007bff;">YOUR OPENING LINE:</h4>
      <p style="margin: 5px 0; font-size: 15px;">"Looking at your ${data.macModel || 'system'}, here's what I'd recommend tackling first: <strong>${criticalFlags[0] ? criticalFlags[0].issue : 'the critical items'}</strong>. The rest can wait until ${moderateCount > 0 ? '[business picks up / after the holidays / next quarter]' : 'later'}."</p>
    </div>
    
    <div style="background: #fff; padding: 15px; margin-top: 15px; border-left: 4px solid #6c757d;">
      <h4 style="margin-top: 0; color: #6c757d;">EXPECTED BUDGET RANGE:</h4>
      <p style="margin: 5px 0;">Total opportunity: <strong>$${totalOpportunity}</strong></p>
      <p style="margin: 5px 0; font-size: 14px; color: #666;">But realistically, if ${systemHealth === 'CRITICAL' ? 'system replacement' : 'targeted fixes'}: ${systemHealth === 'CRITICAL' ? '$1,200-2,000' : '$' + Math.min(totalOpportunity, 800) + '-' + totalOpportunity}</p>
    </div>
  </div>

  <div style="background: #fff; border-radius: 8px; padding: 20px; margin-bottom: 20px;">
    <h2 style="border-bottom: 2px solid #5b7db1; padding-bottom: 10px;">📊 FULL DIAGNOSTIC DUMP</h2>
    
    <h3>SYSTEM INFO:</h3>
    <ul>
      <li>macOS: ${data.osName || 'Unknown'} (${data.osVersion || 'Unknown'})</li>
      <li>Model: ${data.macModel || 'Unknown'}</li>
      <li>CPU: ${data.cpuBrand || 'Unknown'} (${data.physicalCores || 0} cores)</li>
      <li>RAM: ${data.totalRAM || 0} GB</li>
      <li>Storage: ${data.totalStorage || 0} GB ${data.storageType || ''} (${data.freeStoragePercent || 0}% free)</li>
      <li>GPU: ${data.gpuModel || 'Unknown'}</li>
    </ul>

    <h3>HEALTH METRICS:</h3>
    <ul>
      <li>Battery: ${data.batteryCapacity || 100}% capacity, ${data.batteryCycles || 0} cycles (${data.batteryCondition || 'N/A'})</li>
      <li>Last Backup: ${data.lastBackupDate || 'Never'}</li>
      <li>Firewall: ${data.firewallEnabled ? 'ON' : 'OFF'}</li>
      <li>FileVault: ${data.fileVaultEnabled ? 'ON' : 'OFF'}</li>
      <li>SIP (System Integrity Protection): ${data.sipEnabled ? 'ON' : 'OFF'}</li>
      <li>Software Updates: ${data.softwareUpdateStatus || 'Unknown'}</li>
      <li>Login Items: ${data.loginItemsCount || 0} apps</li>
      <li>Memory Pressure: ${data.memoryPressure || 'Unknown'}</li>
      <li>RAM Speed: ${data.ramSpeed || 0} MHz</li>
      <li>Network: ${data.networkType || 'Unknown'}</li>
      <li>WiFi Signal: ${data.wifiSignalStrength || 'Unknown'}</li>
      <li>Display: ${data.displayResolution || 'Unknown'}</li>
      <li>External Monitors: ${data.externalMonitors || 0}</li>
      <li>CPU Temperature: ${data.cpuTemperature || 0}°C${data.cpuTemperature > 0 ? '' : ' (unavailable)'}</li>
    </ul>

    <h3>AI PREPAREDNESS:</h3>
    <ul>
      <li>Tier: ${data.aiPreparednessTier || 'Unknown'}</li>
      <li>System Health: ${systemHealth}</li>
    </ul>
  </div>

  <div style="background: #fff3cd; border: 2px solid #ffc107; border-radius: 8px; padding: 20px; margin-bottom: 20px;">
    <h2 style="margin-top: 0; color: #f57c00;">📞 SALES CALL SCRIPT</h2>
    
    <h3 style="color: #5b7db1; margin-top: 0;">PRE-CALL PREP:</h3>
    <ul style="margin-bottom: 20px;">
      <li><strong>Review flagged issues above</strong> - Know the top 2-3 pain points</li>
      <li><strong>Check their grade:</strong> ${systemHealth} system</li>
      <li><strong>Total opportunity:</strong> $${totalOpportunity} in services</li>
      <li><strong>Decision timeline:</strong> ${criticalCount >= 2 ? 'URGENT - 2-4 weeks' : moderateCount >= 2 ? 'Soon - 1-2 months' : 'Planning - 3-6 months'}</li>
    </ul>
    
    <h3 style="color: #5b7db1;">OPENING (First 30 seconds):</h3>
    <p><strong>YOU:</strong> "Hi ${clientName || '[Name]'}, this is [Your Name] from Dr.WinMac. You ran our Velocity Strip-Search scan on your ${data.macModel || 'Mac'} - do you have a couple minutes to go over what we found?"</p>
    <p style="font-size: 12px; color: #666;"><em>[Wait for confirmation. If busy: "No problem, when's a better time? I have the results in front of me."]</em></p>
    
    <h3 style="color: #5b7db1;">HOOK (Lead with their top issue):</h3>
    <p><strong>YOU:</strong> "${callScriptHook}"</p>
    <p style="font-size: 12px; color: #666;"><em>[Pause. Let them respond. Listen for frustration, workflow impacts, or urgency.]</em></p>
    
    <h3 style="color: #5b7db1;">QUALIFY (Understand their world):</h3>
    <p><strong>YOU:</strong> "Quick question - is this Mac primarily for work, personal use, or both?"</p>
    <p style="font-size: 12px; color: #666;"><em>[If work: "What kind of work?" / If personal: "What do you mainly use it for?"]</em></p>
    <p><strong>FOLLOW-UP:</strong> "On a scale of 1-10, how much is [issue from hook] slowing you down day-to-day?"</p>
    <p style="font-size: 12px; color: #666;"><em>[Listen for 7+: that's real pain. Under 5: deprioritize.]</em></p>
    
    <h3 style="color: #5b7db1;">PRESENT SOLUTION:</h3>
    <p><strong>YOU:</strong> "Based on what you're telling me, here's what I'd recommend..."</p>
    <ul style="margin-top: 10px;">
      <li><strong>If ${systemHealth === 'CRITICAL' || systemHealth === 'NEEDS_ATTENTION' ? 'critical issues' : 'multiple flags'}:</strong> "Let's get you on Jeremy's calendar for a free 15-minute consult. He'll walk through your options - whether that's targeted upgrades or budgeting for replacement."</li>
      <li><strong>If service opportunity:</strong> "We can handle [backup setup / security hardening / performance tuning] same-week. Usually takes 45 min - 1 hour remotely."</li>
      <li><strong>If just needs education:</strong> "I can send you our maintenance checklist. If you get stuck on any of it, we're a phone call away."</li>
    </ul>
    
    <h3 style="color: #5b7db1;">CLOSE (Assume the sale):</h3>
    <p><strong>YOU:</strong> "I'm looking at Jeremy's calendar - I have [Day] at [Time] or [Day] at [Time]. Which works better for you?"</p>
    <p style="font-size: 12px; color: #666;"><em>[If they hesitate: "No pressure - what questions can I answer to help you decide?"]</em></p>
    
    <h3 style="color: #d32f2f; margin-top: 20px;">OBJECTION HANDLING:</h3>
    <table style="width: 100%; border-collapse: collapse;">
      <tr style="border-bottom: 1px solid #ddd;">
        <td style="padding: 8px; font-weight: bold; width: 200px;">"Too expensive"</td>
        <td style="padding: 8px;">"I hear you. Most clients tell us they save 2-3 hours/week after we optimize their setup. What's your time worth per hour? Let's do the math together."</td>
      </tr>
      <tr style="border-bottom: 1px solid #ddd;">
        <td style="padding: 8px; font-weight: bold;">"I'll do it myself"</td>
        <td style="padding: 8px;">"Totally respect that! Want me to email you our step-by-step guide? If you hit any snags, we're here. No judgment."</td>
      </tr>
      <tr style="border-bottom: 1px solid #ddd;">
        <td style="padding: 8px; font-weight: bold;">"Need to think about it"</td>
        <td style="padding: 8px;">"Of course. What specific part are you mulling over - the cost, the timing, or something else? Let me address that for you."</td>
      </tr>
      <tr style="border-bottom: 1px solid #ddd;">
        <td style="padding: 8px; font-weight: bold;">"Just had Apple look at it"</td>
        <td style="padding: 8px;">"Great! What did they recommend? [Listen] We specialize in the stuff Apple doesn't cover - like ${criticalFlags.length > 0 ? criticalFlags[0].clientFacing : 'backup optimization and performance tuning'}. Did they mention that?"</td>
      </tr>
      <tr style="border-bottom: 1px solid #ddd;">
        <td style="padding: 8px; font-weight: bold;">"It's working fine for me"</td>
        <td style="padding: 8px;">"That's good to hear! The scan flagged a few things that could cause problems down the road - mainly ${criticalFlags.length > 0 ? criticalFlags[0].clientFacing.toLowerCase() : 'preventative stuff'}. Want me to send you a heads-up timeline so you can plan ahead?"</td>
      </tr>
      <tr>
        <td style="padding: 8px; font-weight: bold;">"Can I just buy a new Mac?"</td>
        <td style="padding: 8px;">"Absolutely! That's one of the options Jeremy helps people evaluate. He'll show you what you'd need to spend new vs. what targeted upgrades would cost. Usually saves people $500-1000 if we can extend what you have."</td>
      </tr>
    </table>
    
    <p style="margin-top: 20px; padding: 15px; background: #fff; border-left: 4px solid #5b7db1;"><strong>KEY PRINCIPLE:</strong> You're a consultant, not a salesperson. Your job is to help them make an informed decision - even if that decision is "do nothing." Trust builds repeat business.</p>
  </div>

  <div style="background: #e3f2fd; border-radius: 8px; padding: 20px; margin-top: 20px; text-align: center;">
    <a href="mailto:${clientEmail}" style="display: inline-block; background: #5b7db1; color: white; padding: 15px 30px; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 10px;">📧 Reply to Lead</a>
  </div>

</body>
</html>
  `;

  return html;
}

// ========== API ENDPOINT ==========

app.post('/scan-results', async (req, res) => {
  try {
    const data = req.body;

    if (!data.clientEmail && !data.email) {
      return res.status(400).json({ error: 'Missing client email' });
    }

    const clientEmail = data.clientEmail || data.email;

    // Analyze scan results
    const analysis = analyzeScanResults(data);

    console.log(`📊 New scan from ${clientEmail} - Priority: ${analysis.priorityLevel} (${analysis.priorityScore}/10)`);
    console.log(`System Health: ${analysis.systemHealth}`);
    console.log(`Flags: ${analysis.criticalCount} critical, ${analysis.moderateCount} moderate`);

    // Generate emails
    const clientEmailHTML = generateClientEmail(data, analysis);
    const internalEmailHTML = generateInternalEmail(data, analysis);

    // Send email to CLIENT
    const clientEmailResponse = await resend.emails.send({
      from: 'Velocity Strip-Search <scanner@drwinmac.tech>',
      to: clientEmail,
      subject: '✅ Your Mac Analysis Results',
      html: clientEmailHTML
    });

    // Send email to YOU (Jeremy)
    const internalEmailResponse = await resend.emails.send({
      from: 'Velocity Leads <leads@drwinmac.tech>',
      to: 'Jeremy@drwinmac.tech',
      subject: `🎯 ${analysis.priorityLevel} LEAD: ${clientEmail} - ${analysis.systemHealth} - $${analysis.totalOpportunity}+`,
      html: internalEmailHTML
    });

    console.log('✅ Emails sent successfully');

    res.json({ 
      success: true,
      message: 'Scan results processed and emails sent',
      priority: analysis.priorityLevel,
      systemHealth: analysis.systemHealth,
      flagCount: analysis.flagCount,
      clientEmailId: clientEmailResponse.data?.id,
      internalEmailId: internalEmailResponse.data?.id
    });

  } catch (error) {
    console.error('❌ Error processing scan:', error);
    res.status(500).json({ 
      error: 'Failed to process scan results', 
      details: error.message 
    });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'velocity-strip-search', version: '2.0' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Velocity Strip-Search Backend running on port ${PORT}`);
  console.log(`📧 Email service: ${process.env.RESEND_API_KEY ? 'CONFIGURED' : 'MISSING API KEY'}`);
  console.log(`💎 Trust > Sales - Honest assessments build real relationships`);
});
