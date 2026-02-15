import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import JoinPage from './pages/JoinPage'; // 라우터 등록
import LoginPage from './pages/LoginPage';
import CookiePage from './pages/CookiePage';

import './App.css';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/join" element={<JoinPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/cookie" element={<CookiePage />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
